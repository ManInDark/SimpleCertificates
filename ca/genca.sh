ssh-keygen -f ca
echo "@cert-authority * $(cat ca.pub)" >> ~/.ssh/known_hosts