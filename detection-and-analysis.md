# Detection and Analysis

This tutorial covers the TryHackMe room *Detection and Analysis* from 2026. The practical portion of this challenge focuses on using Splunk to investigate a compromised account.

Link to room:
https://tryhackme.com/room/detectionandanalysis

This particular room is Part 2 of a 4-part Module. It is recommended that you complete the first room, *Preparation*, before tackling this room.

Link to Preparation:
https://tryhackme.com/room/irpreparation



## Task 2: Detection and Analysis [Background Information]

The room asks us two fundamental questions: 

-   Did a security incident occur, and how did the attacker get in?
-   What is the full extent of the damage?

Once the incident is actually confirmed, more specific questions must be asked:

-   How did the attacker gain initial access?
-   Which accounts and systems were affected?
-   What data may have been accessed or exfiltrated?
-   What actions did the attacker take after gaining access?

Questions:

What term describes the process of confirming a security incident has actually occurred?

> Answer: Detection

What term describes the process of understanding the full extent of an incident, including affected accounts, systems, and data?

> Answer: Analysis

# ## Task 3: IR  Triggers and Communication

Here's a list of common IR triggers:

> SOC  alert escalation - SIEM  flags an anomalous sign-in, L1 analyst confirms a true positive, and escalates to L2

> User report - Employee reports receiving a suspicious email or notices unexpected account activity

> Automated detection - EDR  detects and blocks malicious process execution on an endpoint

> Third-party notification - A threat intelligence provider or law enforcement notifies the organization of a compromise

> Threat intelligence feed - IOC  matching the organization's infrastructure appears in an external feed

Additional information from the TryHackMe room:

> Team Communication During  IR
> 
> Effective communication is as important as technical skill during an active incident. Common communication failures that slow down  IR  investigations include:
> 
>> -   Delayed escalation because no clear escalation path is defined
>>-   Key people not being notified because contact lists are outdated
>>-   IT teams unable to provide log access for hours due to approval processes
>>-   MSSP or third-party providers taking days to respond to access requests
>>-   Verbal updates that are never documented, creating gaps in the evidence trail.
>
>These delays have real consequences. Every hour an attacker remains uncontained is an hour they can use to deepen their access, exfiltrate more data, or establish additional  persistence. A well-defined communication plan with clear escalation timelines directly reduces the time between detection and containment. As you saw in the  [Preparation](https://tryhackme.com/room/irpreparation)  room, Nexus Financial's  IR  policy does not currently define a maximum response time between incident declaration and initial containment, a gap that will matter in this investigation.
>
>Ticketing systems play an important role in keeping communication organized. Every action taken, every finding made, and every decision reached during the investigation should be logged in a ticket. This creates an auditable trail that supports post-incident review and lessons learned documentation.

Questions:

What type of IR trigger would a threat intelligence provider notifying an organization of a compromise be classified as?

> Answer: Third-party notification

What system should be used to log every action, finding, and decision made during an IR investigation?

>Ticketing System

# Asset Inventory and IOC tracker

Asset inventories are critical for proper analysis. It is vital to know every system, device, and platform that exists within an organization.

During the investigation, an IOC Tracker should be created and updated throughout each phase of an investigation. The information collected in this document will then be used for containment, eradication, and recovery.

Here are some common IOC types, along with an example of each:

* IP Address -- attacker's sign-in IP is flagged as malicious (outside of the corporate IP, outside of a particular geographic region, etc.)
* Domain -- a phishing domain used to capture and harvest user credentials
* Email Address -- sender address used to deliver phishing (or otherwise malicious) emails
* User Account -- compromised accounts that are used by the attacker
* File Name -- malicious files that were either downloaded of accessed during an attack

Questions:

What does IOC stand for?

>Indicator of Compromise

What IR tool provides a running record of every malicious indicator discovered during an investigation?

> IOC Tracker

# Task 5: Current Incident Context

An anomalous sign-in alert was raised by the SIEM platform and triaged by the L1 analyst. The alert was confirmed as a true positive and was escalated.

Our role in this challenge is to act as the L2 analyst responsible for finding the L1's findings, and leading the full IR investigation.

Here are the details of the SIEM alert:
>-   **Alert Name:**  Anomalous Sign-in Detected
>-   **Time:**  2026-03-30 16:41:30
>-   **Affected Account:**  l.chen@nexusfinancial.thm
>-   **Corporate IP:**  197.32.45.112

Here's what the escalation ticket looks like:

>A SIEM alert triggered on a successful sign-in to a Nexus Financial user account from an IP address that was never observed in the environment before. All Nexus Financial employees work from the London office (IP: 197.32.45.112) and are expected to sign in from the corporate network. This sign-in came from outside the United Kingdom. Laura Chen (Finance Manager) has confirmed she did not initiate this sign-in. Initial triage indicates this is a true positive requiring full IR investigation.  
>
>**Escalation Details:**

>-   **Ticket ID:**  NXF-SOC-2026-0312
>-   **Raised by:**  Marcus Webb, Security Analyst (L1)
>-   **Assigned to:**  IR  Analyst (L2)
>-   **Severity:**  High
>-   **Affected Account:**  l.chen@nexusfinancial.thm

Various M265 logs have been ingested into Splunk under the index **ir**.

Here are the logs available for the practical portion of this challenge:

* Entra ID Sign-in Logs
>sourcetype: azure:aad:signin
>Key Fields: `userPrincipalName`, `ipAddress`, `location.city`, `location.countryOrRegion`, `appDisplayName`, `status.errorCode`

* For Message Trace
>sourcetype: o365:reporting:messagetrace
>Key Fields: `Received`, `SenderAddress`, `RecipientAddress`, `Subject`, `Status`, `FromIP`

* Unified Audit Logs
>sourcetype: o365:management:activity
>Key Fields: `Operation`, `UserId`, `Workload`, `ClientIP`, `ObjectId`, `SourceFileName`, `Name`, `SubjectContainsWords`, `DeleteMessage`

The Key Fields should be searched together. For a clean presentation, you can utilize the following within the "New Search" box in the Search page on the Splunk interface:

> |  table _time Received, SenderAddress, RecipientAddress, Subject, Status, FromIP

The suspicious sign-on is for the account l.chen@nexusfinancial.thm.

# Task 6: Detection Practical

#### Question 1 - What was the IP address from which these suspicious sign-in events originated?

The first step is to search:

> index=ir

Then, we will modify our search with the sourcetype, the userPrincipalName, and add in the Key Fields for the Entra ID sign-in logs.

(Use _Shift+Enter_ for a new line in the Splunk search bar, if you'd like.)

Our updated search should look like this:

> index=ir sourcetype="azure:aad:signin" userPrincipalName="l.chen@nexusfinancial.thm"
|  table _time userPrincipalName, ipAddress, location.city, location.countryOrRegion, appDisplayName, status.errorCode

This shows 81 events. We now want to narrow this down to reveal IPs that are outside of the corporate IP, because everything on the first page is showing results from 197.32.45.112 (the corporate IP).

To do this, we'll add one more filter to the top line of the search: 

> ipAddress!="197.32.45.112"

Make sure that the _A_ in address is capitalized. The search function is case-sensitive!

Once we add this filter and search again, we are suddenly met with many results from the Netherlands.

<img width="924" height="550" alt="Screen Shot 2026-06-11 at 12 01 18 PM" src="https://github.com/user-attachments/assets/fed81deb-e5d4-441f-9ea4-33a5b706591a" />

#### Question 2 - What city did the suspicious sign-in originate from?

This answer can be found in the same search results.

<img width="924" height="550" alt="Screen Shot 2026-06-11 at 12 01 18 PM" src="https://github.com/user-attachments/assets/fed81deb-e5d4-441f-9ea4-33a5b706591a" />


#### Question 3 - What was the exact timestamp of the first suspicious sign-in on Laura Chen's account? (Format: YYYY-MM-DD HH:MM:SS)

The search results should already be sorted by time. However, the first entry is not what we're looking for. Looking at the status.errorCode column, we see that the first result has a code 50140.

What we need to look for, though, is the first event that has an error code of 0. Therefore, we need to take the timestamp from the 2nd event.

<img width="1049" height="649" alt="Screen Shot 2026-06-11 at 12 08 55 PM" src="https://github.com/user-attachments/assets/86939160-6d1c-4dcf-9d9e-44444ca81ded" />

#### What was the subject line of the email delivered to Laura Chen before the suspicious sign-in?

To look at details of the emails delivered, we will adjust our Splunk search.

The index remains the same, but the sourcetype will now be o365:reporting:messagetrace, along with the relevant key fields.

Add all of it together into the search bar and search it.

> index=ir sourcetype="o365:reporting:messagetrace" RecipientAddress="l.chen@nexusfinancial.thm"
|  table _tiime Received, SenderAddress, RecipientAddress, Subject, Status, FromIP

There's one particular email that plays on the sense of urgency, and comes from a different domain. This is the malicious email that we're looking for.

<img width="1660" height="737" alt="Screen Shot 2026-06-11 at 12 15 22 PM" src="https://github.com/user-attachments/assets/23749689-e53d-4a99-9aa6-3511ae4e29f6" />

#### What was the sender domain of the phishing email?

One domain is imitating the real domain for Nexus Financial, and the Subject line of the email is stereotypically phish-y.

<img width="1659" height="754" alt="Screen Shot 2026-06-11 at 12 15 32 PM" src="https://github.com/user-attachments/assets/4a091314-7855-4b62-b729-52885ba29820" />
