.. SPDX-License-Identifier: GPL-2.0

=====================
Multipath TCP (MPTCP)
多路径TCP (MPTCP)
=====================

Introduction
介绍
============

Multipath TCP or MPTCP is an extension to the standard TCP and is described in
`RFC 8684 (MPTCPv1) <https://www.rfc-editor.org/rfc/rfc8684.html>`_. It allows a
device to make use of multiple interfaces at once to send and receive TCP
packets over a single MPTCP connection. MPTCP can aggregate the bandwidth of
multiple interfaces or prefer the one with the lowest latency, it also allows a
fail-over if one path is down, and the traffic is seamlessly reinjected on other
paths.

多路径TCP或MPTCP是标准TCP的扩展，在
`RFC 8684 (MPTCPv1) <https://www.rfc-editor.org/rfc/rfc8684.html>`_ 中描述。它允
许设备同时使用多个接口通过一条MPTCP连接来发送和接收TCP数据包。MPTCP可以聚合多个
接口的带宽或优先选择延迟最低的接口，如果一条路径发生故障，它还允许故障转移，并且
流量会无缝地重新注入其他路径。

For more details about Multipath TCP in the Linux kernel, please see the
official website: `mptcp.dev <https://www.mptcp.dev>`.

有关Linux内核中多路径TCP的更多详细信息，请参见官方网站：
`mptcp.dev <https://www.mptcp.dev>`。

Use cases
用例
=========

Thanks to MPTCP, being able to use multiple paths in parallel or simultaneously
brings new use-cases, compared to TCP:

得益于 MPTCP，与 TCP 相比，能够并行或同时使用多条路径带来了新的用例：

- Seamless handovers: switching from one path to another while preserving
  established connections, e.g. to be used in mobility use-cases, like on
  smartphones.
- Best network selection: using the "best" available path depending on some
  conditions, e.g. latency, losses, cost, bandwidth, etc.
- Network aggregation: using multiple paths at the same time to have a higher
  throughput, e.g. to combine fixed and mobile networks to send files faster.

- 无缝切换：从一条路径切换到另一条路径，同时保留已建立的连接，例如用于智能手机等
  移动用例。

- 最佳网络选择：根据某些条件（例如延迟、损耗、成本、带宽等）使用“最佳”可用路径。

- 网络聚合：同时使用多条路径以获得更高的吞吐量，例如结合固定和移动网络以更快地发
  送文件。

Concepts
概念
========

Technically, when a new socket is created with the ``IPPROTO_MPTCP`` protocol
(Linux-specific), a *subflow* (or *path*) is created. This *subflow* consists of
a regular TCP connection that is used to transmit data through one interface.
Additional *subflows* can be negotiated later between the hosts. For the remote
host to be able to detect the use of MPTCP, a new field is added to the TCP
*option* field of the underlying TCP *subflow*. This field contains, amongst
other things, a ``MP_CAPABLE`` option that tells the other host to use MPTCP if
it is supported. If the remote host or any middlebox in between does not support
it, the returned ``SYN+ACK`` packet will not contain MPTCP options in the TCP
*option* field. In that case, the connection will be "downgraded" to plain TCP,
and it will continue with a single path.

从技术上讲，当使用 ``IPPROTO_MPTCP`` 协议（特定于Linux）创建新套接字时，会创建一
个 *子流*（或 *路径*）。此 *子流* 由常规TCP连接组成，用于通过一个接口传输数据。
主机之间稍后可以协商其他 *子流*。为了使远程主机能够检测到MPTCP的使用，在底层TCP
*子流* 的 TCP *选项* 字段中添加了一个新字段。除其他内容外，此字段还包含一个
``MP_CAPABLE`` 选项，该选项告知另一台主机在支持 MPTCP 的情况下使用 MPTCP。如果远
程主机或其间的任何中间设备不支持 MPTCP，则返回的 ``SYN+ACK`` 数据包将不会在TCP
*选项* 字段中包含 MPTCP 选项。在这种情况下，连接将“降级”为普通 TCP，并将继续使用
单一路径。

This behavior is made possible by two internal components: the path manager, and
the packet scheduler.

此行为由两个内部组件实现：路径管理器和数据包调度程序。

Path Manager
路径管理器
------------

The Path Manager is in charge of *subflows*, from creation to deletion, and also
address announcements. Typically, it is the client side that initiates subflows,
and the server side that announces additional addresses via the ``ADD_ADDR`` and
``REMOVE_ADDR`` options.

路径管理器负责*子流*，从创建到删除，以及地址公告。通常，客户端会启动子流，而服务
器端会通过“ADD_ADDR”和“REMOVE_ADDR”选项公告其他地址。

Path managers are controlled by the ``net.mptcp.pm_type`` sysctl knob -- see
mptcp-sysctl.rst. There are two types: the in-kernel one (type ``0``) where the
same rules are applied for all the connections (see: ``ip mptcp``) ; and the
userspace one (type ``1``), controlled by a userspace daemon (i.e. `mptcpd
<https://mptcpd.mptcp.dev/>`_) where different rules can be applied for each
connection. The path managers can be controlled via a Netlink API, see
netlink_spec/mptcp_pm.rst.

路径管理器由 ``net.mptcp.pm_type`` sysctl 旋钮控制 - 请参阅mptcp-sysctl.rst。有
两种类型：内核类型（类型 ``0``），其中所有连接都应用相同的规则（请参阅：
``ip mptcp``）；用户空间类型（类型 ``1``），由用户空间守护进程（即 `mptcpd
<https://mptcpd.mptcp.dev/>`_）控制，其中可以为每个连接应用不同的规则。路径管理
器可以通过 Netlink API 进行控制，请参阅netlink_spec/mptcp_pm.rst。

To be able to use multiple IP addresses on a host to create multiple *subflows*
(paths), the default in-kernel MPTCP path-manager needs to know which IP
addresses can be used. This can be configured with ``ip mptcp endpoint`` for
example.

为了能够使用主机上的多个 IP 地址来创建多个 *子流*（路径），默认的内核 MPTCP 路径
管理器需要知道可以使用哪些 IP 地址。例如，可以使用``ip mptcp endpoint``进行配置。

Packet Scheduler
包调度器
----------------

The Packet Scheduler is in charge of selecting which available *subflow(s)* to
use to send the next data packet. It can decide to maximize the use of the
available bandwidth, only to pick the path with the lower latency, or any other
policy depending on the configuration.

数据包调度程序负责选择使用哪个可用的*子流*来发送下一个数据包。它可以决定最大限度
地利用可用带宽，只选择延迟较低的路径，或者根据配置选择任何其他策略。

Packet schedulers are controlled by the ``net.mptcp.scheduler`` sysctl knob --
see mptcp-sysctl.rst.

数据包调度程序由“net.mptcp.scheduler”sysctl 旋钮控制 - 参见 mptcp-sysctl.rst。

Sockets API
套接字 API
===========

Creating MPTCP sockets
创建 MPTCP 套接字
----------------------

On Linux, MPTCP can be used by selecting MPTCP instead of TCP when creating the
``socket``:
在 Linux 上，可以在创建``套接字``时选择 MPTCP 而不是 TCP 来使用 MPTCP：

.. code-block:: C

    int sd = socket(AF_INET(6), SOCK_STREAM, IPPROTO_MPTCP);

Note that ``IPPROTO_MPTCP`` is defined as ``262``.
请注意，“IPPROTO_MPTCP”定义为“262”。

If MPTCP is not supported, ``errno`` will be set to:
如果不支持 MPTCP，``errno`` 将设置为：

- ``EINVAL``: (*Invalid argument*): MPTCP is not available, on kernels < 5.6.
- ``EPROTONOSUPPORT`` (*Protocol not supported*): MPTCP has not been compiled,
  on kernels >= v5.6.
- ``ENOPROTOOPT`` (*Protocol not available*): MPTCP has been disabled using
  ``net.mptcp.enabled`` sysctl knob, see mptcp-sysctl.rst.

- ``EINVAL``：（*无效参数*）：在内核 < 5.6 上，MPTCP 不可用。
- ``EPROTONOSUPPORT``（*不支持协议*）：在内核 >= v5.6 上，MPTCP 尚未编译。
- ``ENOPROTOOPT``（*协议不可用*）：已使用
``net.mptcp.enabled`` sysctl 旋钮禁用 MPTCP，请参阅 mptcp-sysctl.rst。

MPTCP is then opt-in: applications need to explicitly request it. Note that
applications can be forced to use MPTCP with different techniques, e.g.
``LD_PRELOAD`` (see ``mptcpize``), eBPF (see ``mptcpify``), SystemTAP,
``GODEBUG`` (``GODEBUG=multipathtcp=1``), etc.

Switching to ``IPPROTO_MPTCP`` instead of ``IPPROTO_TCP`` should be as
transparent as possible for the userspace applications.

Socket options
--------------

MPTCP supports most socket options handled by TCP. It is possible some less
common options are not supported, but contributions are welcome.

Generally, the same value is propagated to all subflows, including the ones
created after the calls to ``setsockopt()``. eBPF can be used to set different
values per subflow.

There are some MPTCP specific socket options at the ``SOL_MPTCP`` (284) level to
retrieve info. They fill the ``optval`` buffer of the ``getsockopt()`` system
call:

- ``MPTCP_INFO``: Uses ``struct mptcp_info``.
- ``MPTCP_TCPINFO``: Uses ``struct mptcp_subflow_data``, followed by an array of
  ``struct tcp_info``.
- ``MPTCP_SUBFLOW_ADDRS``: Uses ``struct mptcp_subflow_data``, followed by an
  array of ``mptcp_subflow_addrs``.
- ``MPTCP_FULL_INFO``: Uses ``struct mptcp_full_info``, with one pointer to an
  array of ``struct mptcp_subflow_info`` (including the
  ``struct mptcp_subflow_addrs``), and one pointer to an array of
  ``struct tcp_info``, followed by the content of ``struct mptcp_info``.

Note that at the TCP level, ``TCP_IS_MPTCP`` socket option can be used to know
if MPTCP is currently being used: the value will be set to 1 if it is.


Design choices
==============

A new socket type has been added for MPTCP for the userspace-facing socket. The
kernel is in charge of creating subflow sockets: they are TCP sockets where the
behavior is modified using TCP-ULP.

MPTCP listen sockets will create "plain" *accepted* TCP sockets if the
connection request from the client didn't ask for MPTCP, making the performance
impact minimal when MPTCP is enabled by default.
