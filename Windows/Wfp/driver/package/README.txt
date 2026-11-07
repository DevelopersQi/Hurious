Furious WFP driver package notice
=================================

This ZIP contains FuriousWfpCallout.sys, built for Windows 10 x64 from the
same source revision as the Furious application.

IMPORTANT: this is an UNSIGNED development/validation driver binary.
It is included in the ZIP for packaging completeness and future validation
only. Furious does not install, register, start, or load this driver.

A normal Windows 10 installation may reject this unsigned driver. Do not enable
Windows test mode, disable Secure Boot, disable Memory Integrity, or weaken
Windows security settings to use it.

The WFP transparent-redirection feature remains disabled unless a separately
signed and validated driver package is provided. Ordinary proxy backends remain
available without this driver.

The current driver does not provide complete transparent interception of
arbitrary unconnected UDP sendto/WSASendTo traffic. UDP production routing must
remain disabled until end-to-end Windows 10 validation is complete.

SHA-256 is recorded in FuriousWfpCallout.sha256.
