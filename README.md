# kotlin-pem-example
Simple project which will load a CA and user certificate from PEM files, without using any keytool hacks.

This will load a PEM certificate authority, load a user certificate, and make a sample API call to
some distant, remote API server of doom.

Things to note:

* The CA certificate is provided in PEM format.
* The user certificate and key are provided in PEM format.
* It's using filenames that are common to Kubernetes, intended to be mounted as a secret.

# Dockerfile

There's a Dockerfile which will build a multi-arch image and upload it to my Docker repository.
There's also one which will build a local image only if you want to play with the code, but I
suspect all you want to do is use this as a reference.

# Kubernets deployment

There's also a sample Kubernetes manifest which you can use to deploy the server and the client.  The client
will run and make an API call, print the results, and then sleep forever.
