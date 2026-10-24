FROM jenkins/jenkins:lts-jdk17

RUN jenkins-plugin-cli --plugins mailer
COPY init.groovy /usr/share/jenkins/ref/init.groovy.d/01-redposture-review.groovy
