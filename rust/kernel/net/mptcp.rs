// SPDX-License-Identifier: GPL-2.0

use crate::{
    prelude::*,
};

/// Options for creating a mptcp sched.

pub struct MptcpSchedOps {
    /// The name of the mptcp sched.
    pub name: &'static CStr,
}

impl MptcpSchedOps {
    fn init();
}
