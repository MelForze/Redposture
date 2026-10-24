import hudson.model.FreeStyleProject
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import hudson.tasks.Shell
import hudson.tasks.ArtifactArchiver
import jenkins.model.Jenkins

def jenkins = Jenkins.get()
def realm = new HudsonPrivateSecurityRealm(false)
realm.createAccount('admin', 'admin')
jenkins.setSecurityRealm(realm)
def authorization = new FullControlOnceLoggedInAuthorizationStrategy()
authorization.setAllowAnonymousRead(false)
jenkins.setAuthorizationStrategy(authorization)
jenkins.setNumExecutors(1)

def success = jenkins.createProject(FreeStyleProject, 'qa-build')
success.buildersList.add(new Shell('printf "Jenkins review artifact\\n" > report.txt'))
success.publishersList.add(new ArtifactArchiver('report.txt'))
success.save()
success.scheduleBuild2(0)

def failure = jenkins.createProject(FreeStyleProject, 'qa-failing')
failure.buildersList.add(new Shell('echo Jenkins review failure; exit 1'))
failure.save()
failure.scheduleBuild2(0)

jenkins.save()
