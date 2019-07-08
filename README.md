
# EndpointSecurityTest
## Some experiments with EndpointSecurity.framework in macOS Catalina beta

### Intro
*The EndpointSecurity framework* is an awesome new framework in macOS Catalina (10.15). It allows you to monitor (and allow or disallow) events like file executions, file open calls, memory mappings and much more. But from **userspace**! Previously you could only do this from kexts which run in **kernelspace**. Since there's little to no documentation about the new framework from AAPL I decided to write a quick explanation, so you don't have waste time getting it to work. I hope some more official information will be available when macOS 10.15 will be released this fall. :P

### What do I need to do to use the framework?
First of all, your binary needs to run as **root**. That's because `libEndpointSecurity.dylib` otherwise will fail to connect to the EndpointSecurityDriver IOService. Also, don't run your binary within Xcode. 

Second you'll need to add the `com.apple.developer.endpoint-security.client` entitlement to your binary or `endpointsecurityd` won't communicate with you.

~~The last big point you need to do is to solve the functions that EndpointSecurity framework exposes. That's because you can't actually just link the framework yet since just `/usr/lib/libEndpointSecurity.dylib` exists. You can see how I did this [here](https://github.com/shinvou/EndpointSecurityTest/blob/0574edfd30cfa6fdf5e2686ba14fefa7aca7c19b/EndpointSecurityTest/main.m#L14-L58).~~
Actually I just found out that you can link against libEndpointSecurity.tbd in Xcode. I somehow failed to notice it's existence.

**Update for beta 3:**
In beta 3, TCC wants to join in. I manually edited `/Library/Application Support/com.apple.TCC/TCC.db` too add this entry:

service | client | client_type | allowed | prompt_count | csreq | policy_id | indirect_object_identifier_type | indirect_object_code_identity | flags | last_modified
--- | --- | --- | --- | --- | --- | --- | --- | --- | --- | ---
kTCCServiceSystemPolicyAllFiles | /path/to/your/binary | 0 | 1 | 1 | NULL | NULL | NULL | UNUSED | 0 | 1562161810

You'll need to disable SIP to edit this database. Also reboot after editing the database since TCC has a cache somewhere that needs to be refreshed.
Other notes: Deleting a client no longer triggers a kernel panic. It just works now.

### Ok and how do I use it now?
- Create a client via es_new_client(). The block you pass will be your event handler later on, decide what to do with the event in there.
- Clear the cache if you wish with es_clear_cache(). The cache remembers your decisions about e.g. file execution, whether you allow or disallow.
- Now you can subscribe to the event you'd like with es_subscribe(). Remember to unsubscribe the event if you dynamically change the monitoring behavior.
- Create a NSRunLoop or something similar so you'll see the logs and your program makes sense. :P

Ok, that's it basically. You'll find more information in my sample code. Also, don't forget to check the headers at `/Applications/Xcode-beta.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/EndpointSecurity`, you'll find some more goodies there. You'll also see there what ES is capable of.

### And what does your sample code do?
Well, in short my code just logs information about file executions and then allows them. :P

### How do I compile it?
Xcode 11 b2

### License?
Pretty much the BSD license, just don't repackage it and call it your own please!

Also if you do make some changes, feel free to make a pull request and help make things more awesome!

### Contact Info?
If you have any support requests please feel free to email me at shinvou[at]gmail[dot]com.

Otherwise, feel free to follow me on twitter: [@biscoditch](https:///www.twitter.com/biscoditch)!

### Special Thanks
- Apple for giving a shit about beta documentation (joke :P)
- Apple for giving a shit about releasing xnu sources and kdk in time
