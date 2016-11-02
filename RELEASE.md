Release Instructions
====================

Set up Sonatype Account
-----------------------
* Sign up for a Sonatype JIRA account [here](https://issues.sonatype.org)
* Click *Sign Up* in the login box, follow instructions

Get access to repository
------------------------
* Go to [community support](https://issues.sonatype.org/browse/OSSRH)
* Ask for publish rights by creating an issue similar to [this one](https://issues.sonatype.org/browse/OSSRH-16798)
  * You must be logged in to create a new issue
  * Use the *Create* button at the top tab

Set up PGP keys
---------------
* Install GNU Privacy Guard (GPG)
  * GPG is installed by default on Ubuntu systems
  * For other systems, see [GnuPG download page](https://www.gnupg.org/download/)

* Generate the key ```gpg --gen-key```

  * Keep the defaults, but specify a passphrase
  * The passphrase can be random; you just need to remember it long enough to finish the next step
  * One way to make a random passphrase: ```base64 /dev/urandom | head -c20; echo;```

* Find the ID of your public key ```gpg --list-secret-keys```
  * Look for the line with format ```sec   2048R/ABCDEFGH 2015-11-17```
  * The ```ABCDEFGH``` is the ID for your public key

* Upload your public key to a public server: ```gpg --send-keys --keyserver hkp://pgp.mit.edu ABCDEFGH```

Create a Maven settings file
----------------------------
* Create a file at ```$HOME/.m2/settings.xml``` with your passphrase and your sonatype username and password
```
<settings>
  <profiles>
    <profile>
      <id>ossrh</id>
      <activation>
        <activeByDefault>true</activeByDefault>
      </activation>
      <properties>
        <gpg.executable>gpg</gpg.executable>
        <gpg.passphrase>[the password for your gpg key]</gpg.passphrase>
      </properties>
    </profile>
  </profiles>  
  <servers>
    <server>
      <id>ossrh</id>
      <username>[your sonatype account name]</username>
      <password>[your sonatype account password]</password>
    </server>
  </servers>
</settings>
```

Deploy to Sonatype
------------------
* Update all ```pom.xml``` files in the package to the release version you want. Submit a pull request, get it reviewed, and submit
* ```mvn clean install deploy -DperformRelease=true```
* Verify the result [here](https://oss.sonatype.org/#nexus-search;quick~com.google.auth)
  * If there is a problem, undo by ```mvn nexus-staging:drop```
* ```mvn nexus-staging:release -DperformRelease=true```
* Update all ```pom.xml``` files to the new snapshot version (unless it's a bugfix release, we
update from 0.4.0 to 0.5.0-SNAPSHOT)

Publish the release
-------------------
* Go to [Sonatype](https://oss.sonatype.org/) and log in
* Click on *Staging Repositories* on the left
* Filter down to the repository by typing the package's groupId without periods in the search box
  * In our case, ```comgoogleauth```
* Click the *release* button just below the top tabs
* It will take some time (up to 10 minutes) for the package to transition

Special cases
=============

Deploying version not at the head of the repository
---------------------------------------------------
* Check out the version you want to deploy
  * ```git checkout <ref>```
* Make sure all ```pom.xml``` file are not using ```SNAPSHOT``` versions
* Proceed to **Deploy to Sonatype**
