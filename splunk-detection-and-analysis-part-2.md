# Detection and Analysis [Part 2 - Analysis Practical]

This tutorial covers the final practical analysis practical portion from the TryHackMe room *Detection and Analysis*. 

The practical portion of this challenge focuses on using Splunk to investigate a compromised account.

Link to room:
https://tryhackme.com/room/detectionandanalysis

This particular room is Part 2 of a 4-part Module. It is recommended that you complete the first room, *Preparation*, before tackling this room.

Link to Preparation:
https://tryhackme.com/room/irpreparation

**Please view the other walkthrough file for Tasks 1-6.**

## Background Information & Context

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

## Task 7: Analysis Practical

The initial compromise of the account has been confirmed, and we have identified the domain and email address where the phishing email originiated from.

Now, we move on to analysis, where we will determine the scope and extent of the incident, gain a better understanding of what the attacker compromised, and if any other accounts were affected.

We can do a few things to get the answers we need:

1. Find all sign-in activity from the attacker's IP -- we will search across all accounts.
2. Did the attacker take action to secure a foothold, or otherwise find ways to maintain persistence?
3. Review the Unified Audit logs to see what actions were performed from the attacker's IP address.

#### Question 1 - How many Nexus Financial accounts show sign-in activity from the attacker's IP?

TryHackMe's **M365 Monitoring Basics** room will help us with these questions.

https://tryhackme.com/room/m365monitoringbasics

In particular, there are two methods of filtering that will help. First is the method for displaying all sign-in events:

```c
 index=scenario sourcetype="azure:aad:signin"
```

We can also filter to show all failed sign-ins:

```c
index="scenario" sourcetype="azure:aad:signin" "status.errorCode"!=0
| stats count as event_count values(ipAddress) as ip_addresses
 values(appDisplayName) as applications values(status.errorCode) as errorCodes  by userPrincipalName
| sort - event_count
| table applications, userPrincipalName, ip_addresses, errorCodes, event_count
```

Finally, we can filter to show all **successful sign-ins:**

```c
index=scenario sourcetype="azure:aad:signin" "status.errorCode"=0 ipAddress="<ADD-IP-HERE>"
| stats values(ipAddress) as ip_addresses values(appDisplayName) as applications  by userPrincipalName
| table applications, userPrincipalName, ip_addresses
```
We could create a search that looks like this:

```c
index=ir sourcetype="azure:aad:signin" ipAddress!="197.32.45.112"
| stats values(ipAddress) as ip_addresses values(appDisplayName) as applications  by userPrincipalName
| table _time userPrincipalName, ipAddress, location.city, location.countryOrRegion, appDisplayName, status.errorCode
```

We can further simplify this search to simply show applications, the userPrincipalName, and ip_addresses:

```c
index=ir sourcetype="azure:aad:signin" ipAddress!="197.32.45.112"
| stats values(ipAddress) as ip_addresses values(appDisplayName) as applications  by userPrincipalName
| table applications, userPrincipalName, ip_addresses
```

<img width="1658" height="610" alt="Screen Shot 2026-06-11 at 1 16 07 PM" src="https://github.com/user-attachments/assets/20126379-7d46-4bdc-b914-e43965e98adf" />


Two accounts show sign-in activity from the attacker's IP.

#### Question 2 - What is the email address of the second compromised account?

The email address of the second compromised account will be found in the search from above.

<img width="1660" height="678" alt="Screen Shot 2026-06-11 at 1 18 12 PM" src="https://github.com/user-attachments/assets/2601b696-1017-419b-b9ff-a50495808c46" />

#### Question 3 - What is the name of the inbox rule created on Laura Chen's account?

Clear out our search, beginning again with a simple search of just "index=ir" in the search box. Select the "All time" preset if it wasn't already set.

Next, we will add the sourcetype, user_id, and the Key Fields. Enter all of this in the search box and search:

```c
index=ir sourcetype="o365:management:activity" user_id="l.chen@nexusfinancial.thm"
| table _time Operation, UserId, Workload, ClientIP, ObjectId, SourceFileName, Name, SubjectContainsWords, DeleteMessage
```

The room provides a hint for this question, guiding us to look for the operation named "New-InboxRule."

Look in the "Operation" column (you can sort the table by Operation to find it quickly).

<img width="1657" height="447" alt="Screen Shot 2026-06-11 at 1 28 56 PM" src="https://github.com/user-attachments/assets/1258b336-1d64-4793-9b6d-b7099967888c" />

At the end of the ObjectId field, you'll find the name of the inbox rule that was created (3 words). It will also show up in the "Name" column.

<img width="1656" height="513" alt="Screen Shot 2026-06-11 at 1 31 51 PM" src="https://github.com/user-attachments/assets/ec29b1f2-5520-47c5-ad5f-450d74c356dc" />

#### How many Nexus Financial employee accounts received the initial phishing email?

The hint here is to look for "the one coming from the attacker's spoofed email."

We'll use the below search to find messages coming from a specific sender address (the attacker's email):

```c
index=ir sourcetype="o365:reporting:messagetrace" SenderAddress="hr-support@nexus-verify.thm"
| table _time Received, SenderAddress, RecipientAddress, Subject, Status, FromIP
```

<img width="1661" height="453" alt="Screen Shot 2026-06-11 at 1 38 47 PM" src="https://github.com/user-attachments/assets/81e96278-a1b6-478b-b0c6-be4877f74032" />

Therefore, there are 2 employee accounts that received the initial phishing email.

## Conclusion

We traced the attacker's IP address through sign-in logs, identified the specific phishing email that was the source of compromise, identified the accounts that were targets, and prepared information for the Response and Recovery phases.

Thanks for reading!
