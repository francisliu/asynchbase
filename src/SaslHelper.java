package org.hbase.async;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.Channels;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

public class SaslHelper implements ChannelFutureListener {

  private static final Logger LOG = LoggerFactory.getLogger(RegionClient.class);
  final private SaslClient saslClient;
  volatile private boolean isCompleted = false;
  final String clientPrincipalName;
  final Login clientLogin;

  //TODO we should be logging in per instance, must have static context
  public SaslHelper(String iphost) {
    String host = null;
    try {
      host = InetAddress.getByName(iphost).getCanonicalHostName();
      Login.initUserIfNeeded(System.getProperty(Login.LOGIN_CONTEXT_NAME_KEY),
          new ClientCallbackHandler(null));
      clientLogin = Login.getCurrLogin();
    } catch (LoginException e) {
      throw new IllegalStateException("Failed to get login context", e);
    } catch (UnknownHostException e) {
      throw new IllegalStateException("Failed to get login context", e);
    }
    final Principal clientPrincipal =
       (Principal)clientLogin.getSubject().getPrincipals().toArray()[0];
    final String serverPrincipal = System.getProperty("hbase.kerberos.regionserver.principal")
        .replaceAll("_HOST", host);
    LOG.debug("Connecting to "+serverPrincipal);
    final KerberosName clientKerberosName = new KerberosName(clientPrincipal.getName());
    final KerberosName serviceKerberosName = new KerberosName(serverPrincipal);
    final String serviceName = serviceKerberosName.getServiceName();
    final String serviceHostname = serviceKerberosName.getHostName();
    clientPrincipalName = clientKerberosName.toString();
    try {
        saslClient = Subject.doAs(clientLogin.getSubject(),
            new PrivilegedExceptionAction<SaslClient>() {
              public SaslClient run() throws SaslException {
                LOG.info("Client will use GSSAPI as SASL mechanism.");
                String[] mechs = {"GSSAPI"};
                LOG.debug("creating sasl client: client=" + clientPrincipalName +
                    ";service=" + serviceName + ";serviceHostname=" + serviceHostname);
                return Sasl.createSaslClient(mechs, clientPrincipalName, serviceName,
                    serviceHostname, null, null);
              }
            });
    } catch (Exception e) {
      LOG.error("Error creating SASL client", e);
      throw new IllegalStateException("Error creating SASL client", e);
    }
  }

  public void sendHello(Channel channel) {
      byte[] challengeBytes = null;
      if(saslClient.hasInitialResponse())
        try {
          challengeBytes = Subject.doAs(clientLogin.getSubject(),
              new PrivilegedExceptionAction<byte[]>() {
                @Override
                public byte[] run() {
                  try {
                    return saslClient.evaluateChallenge(new byte[0]);
                  } catch (SaslException e) {
                    return null;
                  }
                }
              });
        } catch (PrivilegedActionException e) {
          throw new IllegalStateException("Failed to send rpc hello", e);
        }
      byte[] rpcHeader = {'s', 'r', 'p', 'c', 4};
      byte[] buf = new byte[4 + 1 + 1];
      ChannelBuffer buffer = ChannelBuffers.wrappedBuffer(buf);
      buffer.clear();
      buffer.writeBytes(rpcHeader);
      //code for Kerberos AuthMethod enum in HBaseRPC
      buffer.writeByte(81);
      Channels.write(channel, buffer);
      if(challengeBytes != null) {
        buf = new byte[4 + challengeBytes.length];
        buffer = ChannelBuffers.wrappedBuffer(buf);
        buffer.clear();
        buffer.writeInt(challengeBytes.length);
        buffer.writeBytes(challengeBytes);
        Channels.write(channel, buffer);
      }
  }

  public boolean handleResponse(ChannelBuffer inBuffer, Channel channel) {
    //read state
    int state = inBuffer.readInt();
    //0 is success
    LOG.debug("Got state=" + state);
    if(state != 0) {
      return false;
    }
    //read state
    int len = inBuffer.readInt();
    //0 is success
    LOG.debug("Got len="+len);

    if(!saslClient.isComplete()) {
      final byte[] b = inBuffer.readBytes(len).array();
      byte[] challengeBytes;
      try {
        challengeBytes = Subject.doAs(clientLogin.getSubject(),
            new PrivilegedExceptionAction<byte[]>() {
              @Override
              public byte[] run() {
                try {
                  return saslClient.evaluateChallenge(b);
                } catch (SaslException e) {
                  return null;
                }
              }
            });
      } catch (PrivilegedActionException e) {
        throw new IllegalStateException("Failed to send rpc hello", e);
      }
      if(challengeBytes != null) {
        LOG.debug("-->isSaslCompleted: "+saslClient.isComplete());
        byte[] buf = new byte[4 + challengeBytes.length];
        ChannelBuffer outBuffer = ChannelBuffers.wrappedBuffer(buf);
        outBuffer.clear();
        //code for Kerberos AuthMethod enum in HBaseRPC
        outBuffer.writeInt(challengeBytes.length);
        outBuffer.writeBytes(challengeBytes);
        LOG.debug("-->sending: "+Bytes.pretty(challengeBytes));
        Channels.write(channel, outBuffer);
      }
    }
    if(saslClient.isComplete()) {
      byte[] userBytes = Bytes.UTF8(clientPrincipalName);
      final String klass = "org.apache.hadoop.hbase.ipc.HRegionInterface";
      byte[] classBytes = Bytes.UTF8(klass);
      byte[] buf = new byte[4 + 1 + classBytes.length + 1 + 2 + userBytes.length + 1];

      ChannelBuffer outBuffer = ChannelBuffers.wrappedBuffer(buf);
      outBuffer.clear();
      outBuffer.writerIndex(outBuffer.writerIndex()+4);
      outBuffer.writeByte(classBytes.length);              // 1
      outBuffer.writeBytes(classBytes);      // 44
      //This is part of protocol header
      //true if a user field exists
      //1 is true in boolean
      outBuffer.writeByte(1);
      outBuffer.writeShort(userBytes.length);
      outBuffer.writeBytes(userBytes);
      //true if a reaLuser field exists
      outBuffer.writeByte(0);
      //write length
      outBuffer.setInt(0, outBuffer.writerIndex() - 4);
      LOG.debug("-->sending: "+Bytes.pretty(outBuffer));
      Channels.write(channel, outBuffer);
      isCompleted = true;
    }
    return isCompleted;
  }

  public boolean isComplete() {
    return isCompleted;
  }

  @Override
  public void operationComplete(ChannelFuture channelFuture) throws Exception {
    //To change body of implemented methods use File | Settings | File Templates.
  }

  // The CallbackHandler interface here refers to
  // javax.security.auth.callback.CallbackHandler.
  public static class ClientCallbackHandler implements CallbackHandler {
      private String password = null;

      public ClientCallbackHandler(String password) {
          this.password = password;
      }

      public void handle(javax.security.auth.callback.Callback[] callbacks) throws
          UnsupportedCallbackException {
          for (javax.security.auth.callback.Callback callback : callbacks) {
              if (callback instanceof NameCallback) {
                  NameCallback nc = (NameCallback) callback;
                  nc.setName(nc.getDefaultName());
              }
              else {
                  if (callback instanceof PasswordCallback) {
                      PasswordCallback pc = (PasswordCallback)callback;
                      if (password != null) {
                          pc.setPassword(this.password.toCharArray());
                      } else {
                          LOG.warn("Could not login: the client is being asked for a password, but the " +
                            " client code does not currently support obtaining a password from the user." +
                            " Make sure that the client is configured to use a ticket cache (using" +
                            " the JAAS configuration setting 'useTicketCache=true)' and restart the client. If" +
                            " you still get this message after that, the TGT in the ticket cache has expired and must" +
                            " be manually refreshed. To do so, first determine if you are using a password or a" +
                            " keytab. If the former, run kinit in a Unix shell in the environment of the user who" +
                            " is running this Zookeeper client using the command" +
                            " 'kinit <princ>' (where <princ> is the name of the client's Kerberos principal)." +
                            " If the latter, do" +
                            " 'kinit -k -t <keytab> <princ>' (where <princ> is the name of the Kerberos principal, and" +
                            " <keytab> is the location of the keytab file). After manually refreshing your cache," +
                            " restart this client. If you continue to see this message after manually refreshing" +
                            " your cache, ensure that your KDC host's clock is in sync with this host's clock.");
                      }
                  }
                  else {
                      if (callback instanceof RealmCallback) {
                          RealmCallback rc = (RealmCallback) callback;
                          rc.setText(rc.getDefaultText());
                      }
                      else {
                          if (callback instanceof AuthorizeCallback) {
                              AuthorizeCallback ac = (AuthorizeCallback) callback;
                              String authid = ac.getAuthenticationID();
                              String authzid = ac.getAuthorizationID();
                              if (authid.equals(authzid)) {
                                  ac.setAuthorized(true);
                              } else {
                                  ac.setAuthorized(false);
                              }
                              if (ac.isAuthorized()) {
                                  ac.setAuthorizedID(authzid);
                              }
                          }
                          else {
                              throw new UnsupportedCallbackException(callback,"Unrecognized SASL ClientCallback");
                          }
                      }
                  }
              }
          }
      }
  }
}
