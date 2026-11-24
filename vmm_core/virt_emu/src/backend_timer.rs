// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// VM time must wake the VP independently of its run thread (including in HLT).
pub(super) fn arm(
    deadline: Option<u64>,
    clock: &mut VmTimeAccess,
    timer: &Arc<TimerWake>,
    rearm: bool,
) {
    let deadline = deadline.map(vmcore::vmtime::VmTime::from_100ns);
    if !rearm && clock.get_timeout() == deadline {
        return;
    }
    if let Some(deadline) = deadline {
        clock.set_timeout(deadline);
        let wake = Waker::from(timer.clone());
        if clock
            .poll_timeout(&mut Context::from_waker(&wake))
            .is_ready()
        {
            wake.wake();
        }
    } else {
        clock.cancel_timeout();
    }
}
