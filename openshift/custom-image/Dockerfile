FROM registry.redhat.io/rhpam-7/rhpam-kieserver-rhel8:7.11.1

USER root

RUN mv /opt/eap/bin/openshift-launch.sh /opt/eap/bin/openshift-launch.bak
COPY openshift-launch.sh /opt/eap/bin
RUN chmod +x /opt/eap/bin/openshift-launch.sh

# Run user
USER 185

# Specify the working directory
WORKDIR /home/jboss

# Specify run cmd
CMD ["/opt/eap/bin/openshift-launch.sh"]
