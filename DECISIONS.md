ssh is easier to test end to end, let's try get ssh credential based injection work end to end

you can't make assumption on the SSH server, not always enterprise managed. So RDM already stores fingreprint
I sugguest that we do RDM finger print aware credential injection
that is, if this finger print is new, we do a preflight probe and get the actual fingerprint, then send finger print back to user, after user confirm, we drop it, reconnect via Jmux
you know waht I mean? so even though the SSH client have no knolwedge, RDM can still manipulate this process on UI side

good, let's actually write this down at gateway project root, with all the discussion we had, then commit push to a branch, this is a bit too much, we should do powershell and vnc first
