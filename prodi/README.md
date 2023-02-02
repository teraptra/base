Prodi is a small program to automate the task of:
<ol>
<li>Verify ssh key security (using -sk non recoverable type)</li>
<li>Acquire temporary Vault access token via OIDC browser pop</li>
<li>Request signed daily certificate for public SSH key using token</li>
<li>Store signed pub Cert ?somewhere?</li>
<li>Update SSH agents with new cert</li>
</ol>

It also supports an emergency mode (not yet implemented) to request long lived emergency certs.


(Yes, some of you probably recognize this functionality suite.)