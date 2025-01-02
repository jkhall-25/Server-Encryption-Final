This Project is an implementation of a cryptographically secure server/client protocol. 

To host, run "generate keys" file to generate the RSA keys required for secure communication. Then run server.py to start listening on server. To connect, run client.py and use one of the following user logins:

User: alice Password: aaa
User: bob Password: bbb
User: charlie Password: ccc

The project is set up by default to run on a local machine in two instances of a command shell. To run the server and client on separate computers, change self.server_ip with the help of the commented code on line 18 of server.py and change server_ip on line 14 of client.py to the relevant ip addresses. 
