//! Gives the pages of free page reports back to macOS, where madvise() doesn't release guest
//! memory that the guest has written to. The VMM replaces the reported blocks of guest RAM with
//! fresh memory instead, see `WorkerMessage::ReclaimMemory`.

use std::ops::Range;
use std::os::fd::{AsRawFd, RawFd};
use std::thread;

use crossbeam_channel::{unbounded, Receiver, Sender};
use utils::pollable_channel::{pollable_channel, PollableChannelReciever, PollableChannelSender};
use utils::worker_message::{WorkerMessage, RECLAIM_BLOCK_SIZE};
use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

use super::defs::QUEUE_SIZE;
use super::device::{Balloon, FRQ_INDEX};
use super::{BalloonError, Result};
use crate::virtio::DeviceState;

/// The most reports that the device takes from the queue while earlier ones are still being
/// reclaimed; the others stay in the queue until some are done. A guest that follows the virtio
/// spec never has more of them in flight than the size of the queue.
const MAX_IN_FLIGHT: usize = QUEUE_SIZE as usize;

/// How often the reclaim thread logs how much it has given back.
const LOG_EVERY: u64 = 1 << 30;

/// A range of a free page report that is within a single region of guest memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FreeRange {
    pub(super) guest_addr: GuestAddress,
    /// Where the VMM maps the range.
    pub(super) host_addr: *mut u8,
    pub(super) len: usize,
}

impl FreeRange {
    /// Returns the range of `len` bytes at `guest_addr`, if it's within a single region of
    /// `mem`.
    pub(super) fn new(mem: &GuestMemoryMmap, guest_addr: GuestAddress, len: usize) -> Option<Self> {
        let slice = mem.get_slice(guest_addr, len).ok()?;
        Some(Self {
            guest_addr,
            host_addr: slice.ptr_guard_mut().as_ptr(),
            len,
        })
    }

    fn guest_end(&self) -> GuestAddress {
        GuestAddress(self.guest_addr.0 + self.len as u64)
    }
}

/// Merges the ranges of a report that are adjacent in the same region of guest memory, so that
/// each run of them is released with a single system call.
fn coalesce(mem: &GuestMemoryMmap, mut ranges: Vec<FreeRange>) -> Vec<FreeRange> {
    // Linux fills a report from the free lists of its page allocator, which aren't sorted by
    // address.
    ranges.sort_unstable_by_key(|range| range.guest_addr);
    ranges.dedup_by(|next, prev| {
        if prev.guest_end() != next.guest_addr {
            return false;
        }
        // Two regions can be adjacent in guest memory without being adjacent in the VMM's.
        let Some(merged) = FreeRange::new(mem, prev.guest_addr, prev.len + next.len) else {
            return false;
        };
        *prev = merged;
        true
    });
    ranges
}

/// Smaller or unaligned ranges are only madvise()d, so that the guest can't make the VMM split
/// the stage-2 mapping of its RAM into small pieces, and because the VMM only replaces whole
/// blocks. Linux reports 2 MiB blocks by default.
fn reclaimable(range: &FreeRange) -> bool {
    let len = range.len as u64;
    len != 0
        && range.guest_addr.0.is_multiple_of(RECLAIM_BLOCK_SIZE)
        && len.is_multiple_of(RECLAIM_BLOCK_SIZE)
}

fn madvise(range: &FreeRange) {
    // SAFETY: the range is guest memory, whose contents the guest has given up.
    let ret = unsafe { libc::madvise(range.host_addr.cast(), range.len, libc::MADV_DONTNEED) };
    if ret < 0 {
        error!(
            "balloon: failed to discard reported free pages: {:?}",
            std::io::Error::last_os_error()
        );
    }
}

/// Without a reclaimer, the pages of free page reports are only madvise()d.
#[derive(Default)]
pub(super) struct FreePageReclaim {
    reclaimer: Option<Reclaimer>,
}

struct Reclaimer {
    requests: Sender<ReclaimRequest>,
    done: PollableChannelReciever<u16>,
    /// Reports sent to the thread that aren't done yet.
    in_flight: usize,
}

enum ReclaimRequest {
    Report { head: u16, ranges: Vec<Range<u64>> },
    Flush(Sender<()>),
}

impl FreePageReclaim {
    /// Whether another report can be taken from the queue.
    pub(super) fn can_take_report(&self) -> bool {
        self.reclaimer
            .as_ref()
            .is_none_or(|reclaimer| reclaimer.in_flight < MAX_IN_FLIGHT)
    }

    /// Gives the pages of the report `head` back to the host. Returns true if some of them are
    /// still being reclaimed, in which case the report mustn't be used until
    /// [`FreePageReclaim::take_done`] returns it.
    pub(super) fn release(
        &mut self,
        mem: &GuestMemoryMmap,
        head: u16,
        ranges: Vec<FreeRange>,
    ) -> bool {
        self.release_with(mem, head, ranges, madvise)
    }

    /// Like [`FreePageReclaim::release`], with `discard` giving back each run of adjacent ranges
    /// that isn't reclaimed.
    fn release_with(
        &mut self,
        mem: &GuestMemoryMmap,
        head: u16,
        ranges: Vec<FreeRange>,
        mut discard: impl FnMut(&FreeRange),
    ) -> bool {
        // Each range is given back as it would be on its own: merged with a range that is only
        // madvise()d, one that is reclaimed would end up unaligned and only be madvise()d too.
        let (reclaimed, madvised): (Vec<_>, Vec<_>) = ranges
            .into_iter()
            .partition(|range| self.reclaimer.is_some() && reclaimable(range));
        for range in coalesce(mem, madvised) {
            discard(&range);
        }
        let reclaim_ranges: Vec<_> = coalesce(mem, reclaimed)
            .iter()
            .map(|range| range.guest_addr.0..range.guest_end().0)
            .collect();
        match &mut self.reclaimer {
            Some(reclaimer) if !reclaim_ranges.is_empty() => {
                reclaimer
                    .requests
                    .send(ReclaimRequest::Report {
                        head,
                        ranges: reclaim_ranges,
                    })
                    .unwrap();
                reclaimer.in_flight += 1;
                true
            }
            _ => false,
        }
    }

    /// Returns the head of a report whose ranges have been reclaimed, if there is one.
    fn take_done(&mut self) -> Option<u16> {
        let reclaimer = self.reclaimer.as_mut()?;
        let head = reclaimer.done.try_recv().ok().flatten()?;
        reclaimer.in_flight -= 1;
        Some(head)
    }

    pub(super) fn done_fd(&self) -> Option<RawFd> {
        self.reclaimer.as_ref().map(|r| r.done.as_raw_fd())
    }

    /// Waits for the reports in flight to be reclaimed, and returns their heads.
    pub(super) fn finish(&mut self) -> Vec<u16> {
        let Some(reclaimer) = &mut self.reclaimer else {
            return Vec::new();
        };
        let (flushed, flush_done) = unbounded();
        let _ = reclaimer.requests.send(ReclaimRequest::Flush(flushed));
        let _ = flush_done.recv();
        let mut heads = Vec::new();
        while let Some(head) = self.take_done() {
            heads.push(head);
        }
        if let Some(reclaimer) = &mut self.reclaimer {
            reclaimer.in_flight = 0;
        }
        heads
    }
}

impl Reclaimer {
    fn new(map_sender: Sender<WorkerMessage>) -> Result<Self> {
        let (done_sender, done) = pollable_channel().map_err(BalloonError::EventFd)?;
        let (requests, request_receiver) = unbounded();
        thread::Builder::new()
            .name("balloon reclaim".into())
            .spawn(move || reclaim(request_receiver, map_sender, done_sender))
            .map_err(BalloonError::ReclaimThread)?;
        Ok(Self {
            requests,
            done,
            in_flight: 0,
        })
    }
}

fn reclaim(
    requests: Receiver<ReclaimRequest>,
    map_sender: Sender<WorkerMessage>,
    done: PollableChannelSender<u16>,
) {
    let (mut replaced, mut kept, mut logged) = (0u64, 0u64, 0u64);
    for request in requests {
        let (head, ranges) = match request {
            ReclaimRequest::Report { head, ranges } => (head, ranges),
            ReclaimRequest::Flush(flushed) => {
                let _ = flushed.send(());
                continue;
            }
        };
        for range in ranges {
            let len = range.end - range.start;
            let (reply_sender, reply) = unbounded();
            if map_sender
                .send(WorkerMessage::ReclaimMemory(reply_sender, range.start, len))
                .is_err()
            {
                return;
            }
            // Pages that the VMM couldn't replace are left as they were, which only costs memory.
            match reply.recv() {
                Ok(true) => replaced += len,
                Ok(false) => kept += len,
                Err(_) => return,
            }
        }
        if replaced - logged >= LOG_EVERY {
            info!(
                "balloon: replaced {} MiB of free pages, kept {} MiB",
                replaced >> 20,
                kept >> 20
            );
            logged = replaced;
        }
        if done.send(head).is_err() {
            return;
        }
    }
}

impl Balloon {
    /// Has the VMM replace the reported free pages that make up whole blocks of guest RAM through
    /// `map_sender`, which releases them on macOS. Guest RAM must be mapped in blocks, see
    /// `map_guest_ram_in_blocks`. Must be called before the balloon subscribes to events.
    pub fn replace_free_pages(&mut self, map_sender: Sender<WorkerMessage>) -> Result<()> {
        self.reclaim.reclaimer = Some(Reclaimer::new(map_sender)?);
        info!("balloon: free page reports are replaced with fresh memory");
        Ok(())
    }

    /// Completes the reports in flight, so that the queue holds none of them.
    pub(super) fn finish_reclaims(&mut self) {
        let heads = self.reclaim.finish();
        if heads.is_empty() {
            return;
        }
        let (DeviceState::Activated(ref mem, _), Some(queues)) =
            (&self.device_state, self.queues.as_mut())
        else {
            return;
        };
        for head in heads {
            if let Err(e) = queues[FRQ_INDEX].queue.add_used(mem, head, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
        self.device_state.signal_used_queue();
    }

    pub(super) fn handle_reclaim_done_event(&mut self) {
        let DeviceState::Activated(ref mem, _) = self.device_state else {
            // Reset finished the reports that were in flight.
            while self.reclaim.take_done().is_some() {}
            return;
        };
        let queue = &mut self
            .queues
            .as_mut()
            .expect("queues should exist when activated")[FRQ_INDEX]
            .queue;
        let mut have_used = false;
        while let Some(head) = self.reclaim.take_done() {
            have_used = true;
            if let Err(e) = queue.add_used(mem, head, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
        // Reports may have been left in the queue while too many were in flight, and the guest
        // won't notify the device about them again.
        have_used |= self.process_frq();
        if have_used {
            self.device_state.signal_used_queue();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use super::*;

    const MIB: u64 = 1 << 20;
    const TIMEOUT: Duration = Duration::from_secs(5);

    fn ranges(mem: &GuestMemoryMmap, ranges: &[(u64, usize)]) -> Vec<FreeRange> {
        ranges
            .iter()
            .map(|&(addr, len)| FreeRange::new(mem, GuestAddress(addr), len).unwrap())
            .collect()
    }

    fn reclaim_with_vmm() -> (FreePageReclaim, Receiver<WorkerMessage>) {
        let (map_sender, worker) = unbounded();
        let reclaim = FreePageReclaim {
            reclaimer: Some(Reclaimer::new(map_sender).unwrap()),
        };
        (reclaim, worker)
    }

    fn wait_done(reclaim: &mut FreePageReclaim) -> u16 {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(head) = reclaim.take_done() {
                return head;
            }
            assert!(Instant::now() < deadline, "report not done");
            sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn test_reclaimable() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), (16 * MIB) as usize)]).unwrap();
        let is = |addr, len| reclaimable(&FreeRange::new(&mem, GuestAddress(addr), len).unwrap());
        assert!(is(0, 2 << 20));
        assert!(is(2 * MIB, 4 << 20));
        assert!(!is(0, 0));
        assert!(!is(0, 1 << 20));
        assert!(!is(0, 3 << 20));
        assert!(!is(MIB, 2 << 20));
    }

    #[test]
    fn test_coalesce_merges_adjacent_unsorted_ranges() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), MIB as usize)]).unwrap();
        assert_eq!(
            coalesce(
                &mem,
                ranges(
                    &mem,
                    &[(0x4000, 0x1000), (0x1000, 0x1000), (0x2000, 0x2000)]
                )
            ),
            ranges(&mem, &[(0x1000, 0x4000)])
        );
    }

    #[test]
    fn test_coalesce_keeps_gaps_overlaps_and_regions_apart() {
        let mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), MIB as usize),
            (GuestAddress(MIB), MIB as usize),
        ])
        .unwrap();
        assert_eq!(
            coalesce(
                &mem,
                ranges(
                    &mem,
                    &[
                        (0x1000, 0x1000),
                        (0x3000, 0x2000),
                        (0x4000, 0x1000),
                        (MIB - 0x1000, 0x1000),
                        (MIB, 0x1000),
                    ]
                )
            ),
            ranges(
                &mem,
                &[
                    (0x1000, 0x1000),
                    (0x3000, 0x2000),
                    (0x4000, 0x1000),
                    (MIB - 0x1000, 0x1000),
                    (MIB, 0x1000),
                ]
            )
        );
    }

    #[test]
    fn test_release_without_reclaimer_discards_everything() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), (16 * MIB) as usize)]).unwrap();
        let mut reclaim = FreePageReclaim::default();
        let mut discarded = Vec::new();
        let in_flight = reclaim.release_with(
            &mem,
            0,
            ranges(&mem, &[(2 * MIB, 2 * MIB as usize), (0x1000, 0x1000)]),
            |range| discarded.push(*range),
        );
        assert!(!in_flight);
        assert_eq!(
            discarded,
            ranges(&mem, &[(0x1000, 0x1000), (2 * MIB, 2 * MIB as usize)])
        );
    }

    #[test]
    fn test_release_sends_whole_blocks_to_the_vmm_and_discards_the_rest() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), (16 * MIB) as usize)]).unwrap();
        let (mut reclaim, worker) = reclaim_with_vmm();
        let mut discarded = Vec::new();
        let in_flight = reclaim.release_with(
            &mem,
            7,
            ranges(
                &mem,
                &[
                    (4 * MIB, 2 * MIB as usize),
                    (0x1000, 0x1000),
                    (2 * MIB, 2 * MIB as usize),
                    (9 * MIB, 2 * MIB as usize),
                ],
            ),
            |range| discarded.push(*range),
        );
        assert!(in_flight);
        assert_eq!(
            discarded,
            ranges(&mem, &[(0x1000, 0x1000), (9 * MIB, 2 * MIB as usize)])
        );

        let WorkerMessage::ReclaimMemory(reply, guest_addr, len) =
            worker.recv_timeout(TIMEOUT).unwrap()
        else {
            panic!("unexpected worker message");
        };
        assert_eq!((guest_addr, len), (2 * MIB, 4 * MIB));
        reply.send(true).unwrap();
        assert_eq!(wait_done(&mut reclaim), 7);
        assert!(reclaim.can_take_report());
    }

    #[test]
    fn test_reports_stay_in_the_queue_while_too_many_are_in_flight() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), (16 * MIB) as usize)]).unwrap();
        let (mut reclaim, _worker) = reclaim_with_vmm();
        for head in 0..MAX_IN_FLIGHT as u16 {
            assert!(reclaim.can_take_report());
            assert!(reclaim.release(&mem, head, ranges(&mem, &[(0, 2 * MIB as usize)])));
        }
        assert!(!reclaim.can_take_report());
    }

    #[test]
    fn test_finish_returns_the_reports_in_flight() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), (16 * MIB) as usize)]).unwrap();
        let (mut reclaim, worker) = reclaim_with_vmm();
        let vmm = thread::spawn(move || {
            for message in worker {
                if let WorkerMessage::ReclaimMemory(reply, ..) = message {
                    reply.send(true).unwrap();
                }
            }
        });
        for head in [3, 5] {
            assert!(reclaim.release(&mem, head, ranges(&mem, &[(0, 2 * MIB as usize)])));
        }

        let mut heads = reclaim.finish();
        heads.sort_unstable();
        assert_eq!(heads, [3, 5]);
        assert!(reclaim.can_take_report());
        drop(reclaim);
        vmm.join().unwrap();
    }

    #[test]
    fn test_reclaim_stops_when_vmm_drops_reply() {
        let (requests, request_receiver) = unbounded();
        requests
            .send(ReclaimRequest::Report {
                head: 7,
                ranges: vec![0..2 * MIB, 4 * MIB..6 * MIB],
            })
            .unwrap();
        drop(requests);

        let (map_sender, map_receiver) = unbounded();
        let (done_sender, done) = pollable_channel().unwrap();
        let worker = thread::spawn(move || {
            let message = map_receiver.recv_timeout(TIMEOUT).unwrap();
            assert!(matches!(message, WorkerMessage::ReclaimMemory(..)));
        });

        reclaim(request_receiver, map_sender, done_sender);
        worker.join().unwrap();

        assert_eq!(done.try_recv().unwrap(), None);
    }
}
