# Jenkins Project Response to NVD CWE Analysis

## [CVE-2020-2094](https://nvd.nist.gov/vuln/detail/CVE-2020-2094)

### CWE Assignments

Jenkins Project: **CWE-285: Improper Authorization**  
NVD: **CWE-276: Incorrect Default Permissions**

### Jenkins Project Justification

This is about HTTP request handling, not file permissions.

Use of CWE-862 here is consistent with many other CVEs categorized as CWE-862 that are basically the same problem, like CVE-2022-30954, CVE-2022-30955, CVE-2022-30957, CVE-2022-30959, where NVD assigned the same CWE.

Additionally, NVD inconsistently assigns CWE-276, CWE-281, CWE-668, and CWE-732 for instances of the same problem.


## [CVE-2020-2322](https://nvd.nist.gov/vuln/detail/CVE-2020-2322)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-401: Missing Release of Memory after Effective Lifetime**

### Jenkins Project Justification

The memory leaks and load generation is an intended feature of this plugin, whose name already hints at its purpose. The problem is the missing permission check which allows users other than administrators to trigger the memory leak.


## [CVE-2022-20614](https://nvd.nist.gov/vuln/detail/CVE-2022-20614)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-732: Incorrect Permission Assignment for Critical Resource**

### Jenkins Project Justification

As no permissions are specified for the resource, CWE-862 is a better match than CWE-732. This is also consistent with many other CVEs categorized as CWE-862 that are basically the same problem, like CVE-2022-30954, CVE-2022-30955, CVE-2022-30957, CVE-2022-30959.


## [CVE-2022-20616](https://nvd.nist.gov/vuln/detail/CVE-2022-20616)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-732: Incorrect Permission Assignment for Critical Resource**

### Jenkins Project Justification

As no permissions are specified for the resource, CWE-862 is a better match than CWE-732. This is also consistent with many other CVEs categorized as CWE-862 that are basically the same problem, like CVE-2022-30954, CVE-2022-30955, CVE-2022-30957, CVE-2022-30959.


## [CVE-2022-20618](https://nvd.nist.gov/vuln/detail/CVE-2022-20618)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-732: Incorrect Permission Assignment for Critical Resource**

### Jenkins Project Justification

As no permissions are specified for the resource, CWE-862 is a better match than CWE-732. This is also consistent with many other CVEs categorized as CWE-862 that are basically the same problem, like CVE-2022-30954, CVE-2022-30955, CVE-2022-30957, CVE-2022-30959.


## [CVE-2022-20620](https://nvd.nist.gov/vuln/detail/CVE-2022-20620)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-668: Exposure of Resource to Wrong Sphere**

### Jenkins Project Justification

Use of CWE-862 here is consistent with many other CVEs categorized as CWE-862 that are basically the same problem, like CVE-2022-30954, CVE-2022-30955, CVE-2022-30957, CVE-2022-30959, where NVD assigned the same CWE.

Additionally, NVD inconsistently assigns CWE-276, CWE-281, CWE-668, and CWE-732 for instances of the same problem.


## [CVE-2022-23116](https://nvd.nist.gov/vuln/detail/CVE-2022-23116)

### CWE Assignments

Jenkins Project: **CWE-693: Protection Mechanism Failure**  
NVD: **CWE-311: Missing Encryption of Sensitive Data**

### Jenkins Project Justification

Per the description, encryption did take place. The problem is that the agent-to-controller message allows attackers to decrypt it. There should not be an agent-to-controller callable that allows performing this action. Its existence disables a protection mechanism in the Jenkins remoting library.


## [CVE-2022-23117](https://nvd.nist.gov/vuln/detail/CVE-2022-23117)

### CWE Assignments

Jenkins Project: **CWE-693: Protection Mechanism Failure**  
NVD: **CWE-269: Improper Privilege Management**

### Jenkins Project Justification

Same problem as CWE-2022-23116 in a different part of the code.


## [CVE-2022-23118](https://nvd.nist.gov/vuln/detail/CVE-2022-23118)

### CWE Assignments

Jenkins Project: **CWE-693: Protection Mechanism Failure**  
NVD: **CWE-269: Improper Privilege Management**

### Jenkins Project Justification

Same problem as CWE-2022-23116 in a different component.


## [CVE-2022-25180](https://nvd.nist.gov/vuln/detail/CVE-2022-25180)

### CWE Assignments

Jenkins Project: **CWE-522: Insufficiently Protected Credentials**  
NVD: **CWE-319: Cleartext Transmission of Sensitive Information**

The password is never transmitted in plain text, that's not the problem.


## [CVE-2022-27195](https://nvd.nist.gov/vuln/detail/CVE-2022-27195)

### CWE Assignments

Jenkins Project: **CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory**  
NVD: **CWE-532: Insertion of Sensitive Information into Log File**

### Jenkins Project Justification

It's not a log file.


## [CVE-2022-27199](https://nvd.nist.gov/vuln/detail/CVE-2022-27199)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-276: Incorrect Default Permissions**

### Jenkins Project Justification

This is about HTTP request handling, not file permissions.


## [CVE-2022-27201](https://nvd.nist.gov/vuln/detail/CVE-2022-27201)

### CWE Assignments

Jenkins Project: **CWE-693: Protection Mechanism Failure**  
NVD: **CWE-918: Server-Side Request Forgery (SSRF)**

### Jenkins Project Justification

The initial vulnerability is a protection mechanism bypass, see https://www.jenkins.io/doc/developer/security/remoting-callables/ for documentation.

If this initial vulnerability explanation is rejected, it should still be CWE-611 (XXE) and not CWE-918.


## [CVE-2022-27205](https://nvd.nist.gov/vuln/detail/CVE-2022-27205)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-276: Incorrect Default Permissions**

### Jenkins Project Justification

This is about HTTP request handling, not file permissions.


## [CVE-2022-27206](https://nvd.nist.gov/vuln/detail/CVE-2022-27206)

### CWE Assignments

Jenkins Project: **CWE-256: Plaintext Storage of a Password**  
NVD: **CWE-311: Missing Encryption of Sensitive Data**

### Jenkins Project Justification

CWE-311 is not a child of CWE-256, so it is not "more specific".
<!-- e.g. https://nvd.nist.gov/vuln/cvmap/report/5282 -->

CWE-256 is consistent with numerous other Jenkins project CWEs for the same problem whose NVD analysis resulted in the same CWE, see e.g. CVE-2022-27216, CVE-2022-27217, CVE-2022-28141.


## [CVE-2022-27215](https://nvd.nist.gov/vuln/detail/CVE-2022-27215)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-281: Improper Preservation of Permissions**

### Jenkins Project Justification

Use of CWE-862 here is consistent with many other CVEs categorized as CWE-862 that are basically the same problem, like CVE-2022-30954, CVE-2022-30955, CVE-2022-30957, CVE-2022-30959, where NVD assigned the same CWE.

Additionally, NVD inconsistently assigns CWE-276, CWE-281, CWE-668, and CWE-732 for instances of the same problem.


## [CVE-2022-28137](https://nvd.nist.gov/vuln/detail/CVE-2022-28137)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-732: Incorrect Permission Assignment for Critical Resource**

### Jenkins Project Justification

Use of CWE-862 here is consistent with many other CVEs categorized as CWE-862 that are basically the same problem, like CVE-2022-30954, CVE-2022-30955, CVE-2022-30957, CVE-2022-30959, where NVD assigned the same CWE.

Additionally, NVD inconsistently assigns CWE-276, CWE-281, CWE-668, and CWE-732 for instances of the same problem.


## [CVE-2022-28147](https://nvd.nist.gov/vuln/detail/CVE-2022-28147)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-281: Improper Preservation of Permissions**

### Jenkins Project Justification

Use of CWE-862 here is consistent with many other CVEs categorized as CWE-862 that are basically the same problem, like CVE-2022-30954, CVE-2022-30955, CVE-2022-30957, CVE-2022-30959, where NVD assigned the same CWE.

Additionally, NVD inconsistently assigns CWE-276, CWE-281, CWE-668, and CWE-732 for instances of the same problem.


## [CVE-2022-29049](https://nvd.nist.gov/vuln/detail/CVE-2022-29049)

### CWE Assignments

Jenkins Project: **CWE-20: Improper Input Validation**  
NVD: **CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')**

### Jenkins Project Justification

XSS is only one of the potential resulting impacts, the actual problem is the lack of validation.


## [CVE-2022-30945](https://nvd.nist.gov/vuln/detail/CVE-2022-30945)

### CWE Assignments

Jenkins Project: **CWE-693: Protection Mechanism Failure**  
NVD: **CWE-552: Files or Directories Accessible to External Parties**

### Jenkins Project Justification

From the definition of CWE-552:

> The product makes **files or directories accessible to unauthorized actors**, even though they should not be.
Web servers, FTP servers, and similar servers may store a set of files underneath a "root" directory that is accessible to the server's users.

This issue is unrelated to unauthorized users being able to read files. It is possible to call static methods or constructors defined in Groovy sources found in the classpath of Jenkins core or any plugin while bypassing sandbox allowlist restrictions (as those Groovy sources would be incorrectly loaded by a trusted classloader).


## [CVE-2022-30950](https://nvd.nist.gov/vuln/detail/CVE-2022-30950)

### CWE Assignments

Jenkins Project: **CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer**  
NVD: **CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')**  

### Jenkins Project Justification

Size of input is checked, but incorrectly.


## [CVE-2022-30966](https://nvd.nist.gov/vuln/detail/CVE-2022-30966)

### CWE Assignments

Jenkins Project: **CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')**  
NVD: **CWE-116: Improper Encoding or Escaping of Output**  

### Jenkins Project Justification

Consistency with numerous other CVEs of alike problems on which NVD agrees: CVE-2022-30960, CVE-2022-30961, CVE-2022-30962, CVE-2022-30963, CVE-2022-30964, CVE-2022-30965, CVE-2022-30967, CVE-2022-30968


## [CVE-2022-34175](https://nvd.nist.gov/vuln/detail/CVE-2022-34175)

### CWE Assignments

Jenkins Project: **CWE-693: Protection Mechanism Failure**  
NVD: **CWE-863: Incorrect Authorization**

### Jenkins Project Justification

From the definition of CWE-863:

> The software performs an authorization check when an actor attempts to access a resource or perform an action, but it does not correctly perform the check.

View fragments are not supposed to be accessed directly regardless of what permissions the user has. It was only possible because an existing protection mechanism to prevent request dispatch was incorrectly explicitly disabled.


## [CVE-2022-34796](https://nvd.nist.gov/vuln/detail/CVE-2022-34796)

### CWE Assignments

Jenkins Project: **CWE-862: Missing Authorization**  
NVD: **CWE-522: Insufficiently Protected Credentials**

### Jenkins Project Justification

The credentials are never disclosed here, just the identifiers assigned to them.


## [CVE-2022-36884](https://nvd.nist.gov/vuln/detail/CVE-2022-36884)

### CWE Assignments

Jenkins Project: **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor**  
NVD: **CWE-306: Missing Authentication for Critical Function**

### Jenkins Project Justification

The fix involves a secret token that does not constitute authentication, so the lack of authentication is not the problem. We're rephrasing the Jenkins advisory to make that clearer.


## [CVE-2022-41235](https://nvd.nist.gov/vuln/detail/CVE-2022-41235)

### CWE Assignments

Jenkins Project: **CWE-693: Protection Mechanism Failure**  
NVD: **CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')**

### Jenkins Project Justification

The problem is the agent-to-controller access, not the path traversal.

See documentation at https://www.jenkins.io/doc/developer/security/remoting-callables/


<!--

## [CVE-TODO](httpsTODO)

### CWE Assignments

Jenkins Project: **TODO**  
NVD: **TODO**

### Jenkins Project Justification

TODO


-->
