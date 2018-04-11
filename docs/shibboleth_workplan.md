# Shibboleth workplan

- [x] Set up Shibboleth with Apache in front of DynaFed using the testshib test IdP
- [x] Write tests for Shibboleth authentication
- [x] Investigate using X.509 alongside Shibboleth: Shibboleth completely hijacks auth, can't use X.509 in apache, the IdP can choose to let users use X.509 though, dunno how automatic that is regarding machines. Will probably need to partition the federation into "user" files protected by Shibboleth and "machine" files protected via X.509
- [ ] Apply to UK federation, going through their checklist. Progress: see below
- [ ] Determine whether LIGO wants only Shibboleth for authentication and authorization or if they're okay with us pinging their LDAP server for attributes for authorization
    * [x] If they want us to use Shibboleth only, investigate how to get Shibboleth attributes to Python plugin
    * [x] Then write plugin that parses Shibboleth attributes from keys dict and compares those to JSON similar to LDAP plugin
    * [x] Write tests for Shibboleth authorization plugin
- [ ] Get set up with LIGO federation once we have proof of concept with UK fed


#### Stuff required for UK federation membership

- Go through steps here: https://www.ukfederation.org.uk/content/Documents/Setup2SP
- Get browser facing certificate for DynaFed server
- Get Jens to email federation on our behalf with following info:
    * entityID: https://dynafed.stfc.ac.uk/shibboleth
    * Service Display Name: STFC DynaFed
    * Organisation URL: https://www.scd.stfc.ac.uk/
    * Support contact(s): Alastair Dewhurt alastair.dewhurst@stfc.ac.uk  (handles user problems)
    * Technical contacts(s): Alastair Dewhurt alastair.dewhurst@stfc.ac.uk  (handles technical issues related to SP)
    * Administrative contacts(s): Alastair Dewhurt alastair.dewhurst@stfc.ac.uk  (maintains registration data and ensures policy enforced, can appoint the other two, all three can be same)
    * Automatically generated metadata: provide url or attach file to production server shibboleth metadata 
    * Requested Attributes: (what do we want? what does LIGO provide? This might require some more discussion)
    * Software: Shibboleth SP 2.6.1
    * Logo: https://www.stfc.ac.uk/stfc/includes/themes/MuraSTFC/assets/legacy/2473_web_2.png 
    * Description: Federated access to experimental data stored by STFC (100 char max)
    * Sirtfi compliance (optional): see https://www.ukfederation.org.uk/content/Documents/Sirtfi
    * Security contact(s) (optional): Alastair Dewhurt alastair.dewhurst@stfc.ac.uk
    * Research and Scholarship (R&S) entity category (optional): see https://refeds.org/category/research-and-scholarship
    * Data Protection Code of Conduct (optional): see https://www.ukfederation.org.uk/content/Documents/GeantDPCC
