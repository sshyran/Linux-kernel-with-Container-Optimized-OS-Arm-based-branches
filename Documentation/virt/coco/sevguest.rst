.. SPDX-License-Identifier: GPL-2.0

===================================================================
The Definitive SEV Guest API Documentation
===================================================================

1. General description
======================

The SEV API is a set of ioctls that are used by the guest or hypervisor
to get or set a certain aspect of the SEV virtual machine. The ioctls belong
to the following classes:

 - Hypervisor ioctls: These query and set global attributes which affect the
   whole SEV firmware.  These ioctl are used by platform provisioning tools.

 - Guest ioctls: These query and set attributes of the SEV virtual machine.

2. API description
==================

This section describes ioctls that is used for querying the SEV guest report
from the SEV firmware. For each ioctl, the following information is provided
along with a description:

  Technology:
      which SEV technology provides this ioctl. SEV, SEV-ES, SEV-SNP or all.

  Type:
      hypervisor or guest. The ioctl can be used inside the guest or the
      hypervisor.

  Parameters:
      what parameters are accepted by the ioctl.

  Returns:
      the return value.  General error numbers (-ENOMEM, -EINVAL)
      are not detailed, but errors with specific meanings are.

The guest ioctl should be issued on a file descriptor of the /dev/sev-guest device.
The ioctl accepts struct snp_user_guest_request. The input and output structure is
specified through the req_data and resp_data field respectively. If the ioctl fails
to execute due to a firmware error, then fw_err code will be set otherwise the
fw_err will be set to 0x00000000000000ff.

The firmware checks that the message sequence counter is one greater than
the guests message sequence counter. If guest driver fails to increment message
counter (e.g. counter overflow), then -EIO will be returned.

::

        struct snp_guest_request_ioctl {
                /* Message version number */
                __u32 msg_version;

                /* Request and response structure address */
                __u64 req_data;
                __u64 resp_data;

                /* firmware error code on failure (see psp-sev.h) */
                __u64 fw_err;
        };

2.1 SNP_GET_REPORT
------------------

:Technology: sev-snp
:Type: guest ioctl
:Parameters (in): struct snp_report_req
:Returns (out): struct snp_report_resp on success, -negative on error

The SNP_GET_REPORT ioctl can be used to query the attestation report from the
SEV-SNP firmware. The ioctl uses the SNP_GUEST_REQUEST (MSG_REPORT_REQ) command
provided by the SEV-SNP firmware to query the attestation report.

On success, the snp_report_resp.data will contains the report. The report
contain the format described in the SEV-SNP specification. See the SEV-SNP
specification for further details.

2.2 SNP_GET_DERIVED_KEY
-----------------------
:Technology: sev-snp
:Type: guest ioctl
:Parameters (in): struct snp_derived_key_req
:Returns (out): struct snp_derived_key_resp on success, -negative on error

The SNP_GET_DERIVED_KEY ioctl can be used to get a key derive from a root key.
The derived key can be used by the guest for any purpose, such as sealing keys
or communicating with external entities.

The ioctl uses the SNP_GUEST_REQUEST (MSG_KEY_REQ) command provided by the
SEV-SNP firmware to derive the key. See SEV-SNP specification for further details
on the various fields passed in the key derivation request.

On success, the snp_derived_key_resp.data contains the derived key value. See
the SEV-SNP specification for further details.


2.3 SNP_GET_EXT_REPORT
----------------------
:Technology: sev-snp
:Type: guest ioctl
:Parameters (in/out): struct snp_ext_report_req
:Returns (out): struct snp_report_resp on success, -negative on error

The SNP_GET_EXT_REPORT ioctl is similar to the SNP_GET_REPORT. The difference is
related to the additional certificate data that is returned with the report.
The certificate data returned is being provided by the hypervisor through the
SNP_SET_EXT_CONFIG.

The ioctl uses the SNP_GUEST_REQUEST (MSG_REPORT_REQ) command provided by the SEV-SNP
firmware to get the attestation report.

On success, the snp_ext_report_resp.data will contain the attestation report
and snp_ext_report_req.certs_address will contain the certificate blob. If the
length of the blob is smaller than expected then snp_ext_report_req.certs_len will
be updated with the expected value.

See GHCB specification for further detail on how to parse the certificate blob.

Reference
---------

SEV-SNP and GHCB specification: developer.amd.com/sev

The driver is based on SEV-SNP firmware spec 0.9 and GHCB spec version 2.0.
