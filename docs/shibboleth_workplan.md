# Shibboleth workplan

- [x] Set up Shibboleth with Apache in front of DynaFed using the testShibboleth test IdP
- [ ] Write tests for Shibboleth authentication
- [x] Investigate using X.509 alongside Shibboleth: Shibboleth completely hijacks auth, can't use X.509 in apache, the IdP can choose to let users use X.509 though, dunno how automatic that is regarding machines. Will probably need to partition the federation into "user" files protected by Shibboleth and "machine" files protected via X.509
- [ ] Apply to UK federation, going through their checklist. Progress: see below
- [ ] Determine whether LIGO wants only Shibboleth for authentication and authorization or if they're okay with us pinging their LDAP server for attributes for authorization
 * [ ] If they want us to use Shibboleth only, investigate how to get Shibboleth attributes to Python plugin (probably using headers - secure?)
 * [ ] Then write plugin that parses Shibboleth attributes from keys dict and compares those to JSON similar to LDAP plugin
 * [ ] Write tests for Shibboleth authorization plugin
- [ ] Get set up with LIGO federation once we have proof of concept with UK fed


#### Stuff required for UK federation membership

- Go through steps here: https://www.ukfederation.org.uk/content/Documents/Setup2SP
- Get browser facing certificate for DynaFed server
- Get Jens to email federation on our behalf with following info:
 * entityID: https://dynafed.stfc.ac.uk/shibboleth (I've proposed this - sensible?)
 * Service Display Name: STFC DynaFed (Do we want to be more specific?)
 * Organisation URL: https://www.stfc.ac.uk/ (or do we want SCD? https://www.scd.stfc.ac.uk/)
 * Support contact(s): (handles user problems)
 * Technical contacts(s): (handles technical issues related to SP)
 * Administrative contacts(s): (maintains registration data and ensures policy enforced, can appoint the other two, all three can be same)
 * Automatically generated metadata: https://dynafed.stfc.ac.uk/Shibboleth.sso/Metadata or attach said file
 * Requested Attributes: (what do we want? what does LIGO provide?)
 * Software: Shibboleth SP 2.6.1
 * Logo: https://www.stfc.ac.uk/stfc/includes/themes/MuraSTFC/assets/legacy/2473_web_2.png
 * Description: Federated access to STFC data (100 char max, again, do we want to be more specific?)
 * Sirtfi compliance (optional): see https://www.ukfederation.org.uk/content/Documents/Sirtfi
 * Security contact(s) (optional): see above
 * Research and Scholarship (R&S) entity category (optional): see https://refeds.org/category/research-and-scholarship
 * Data Protection Code of Conduct (optional): see https://www.ukfederation.org.uk/content/Documents/GeantDPCC
