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
import javax.security.auth.login.LoginException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;
import java.util.TreeMap;

final class SecurityHelper implements ChannelFutureListener {

  private static final Logger LOG = LoggerFactory.getLogger(RegionClient.class);
  public static final String SECURITY_AUTHENTICATION_KEY = "hbase.security.authentication";
  public static final String REGIONSERVER_PRINCIPAL_KEY = "hbase.kerberos.regionserver.principal";

  private static int SASL_RPC_ID = -33;

  private final SaslClient saslClient;
  private final String clientPrincipalName;
  private final Login clientLogin;

  private volatile boolean saslCompleted = false;

  private RegionClient regionClient;

  public SecurityHelper(RegionClient regionClient, String iphost) {
    String host = null;
    this.regionClient = regionClient;

    //Login if needed
    try {
      host = InetAddress.getByName(iphost).getCanonicalHostName();
      Login.initUserIfNeeded(System.getProperty(Login.LOGIN_CONTEXT_NAME_KEY),
          new ClientCallbackHandler(null));
    } catch (LoginException e) {
      throw new IllegalStateException("Failed to get login context", e);
    } catch (UnknownHostException e) {
      throw new IllegalStateException("Failed to resolve hostname for: "+iphost, e);
    }

    clientLogin = Login.getCurrLogin();
    final Principal clientPrincipal =
       (Principal)clientLogin.getSubject().getPrincipals().toArray()[0];
    final String serverPrincipal =
        System.getProperty(REGIONSERVER_PRINCIPAL_KEY, "Client")
        .replaceAll("_HOST", host);

    LOG.debug("Connecting to "+serverPrincipal);
    final KerberosName clientKerberosName = new KerberosName(clientPrincipal.getName());
    final KerberosName serviceKerberosName = new KerberosName(serverPrincipal);
    final String serviceName = serviceKerberosName.getServiceName();
    final String serviceHostname = serviceKerberosName.getHostName();
    clientPrincipalName = clientKerberosName.toString();

    //create saslClient
    try {
      final Map<String, String> props =
        new TreeMap<String, String>();
      //sasl configuration
      props.put(Sasl.QOP, "auth");
      props.put(Sasl.SERVER_AUTH, "true");

      saslClient = Subject.doAs(clientLogin.getSubject(),
          new PrivilegedExceptionAction<SaslClient>() {
            public SaslClient run() throws SaslException {
              LOG.info("Client will use GSSAPI as SASL mechanism.");
              String[] mechs = {"GSSAPI"};
              LOG.debug("creating sasl client: client=" + clientPrincipalName +
                  ";service=" + serviceName + ";serviceHostname=" + serviceHostname);
              return Sasl.createSaslClient(mechs, null, serviceName,
                  serviceHostname, props, null);
            }
          });
    } catch (Exception e) {
      LOG.error("Error creating SASL client", e);
      throw new IllegalStateException("Error creating SASL client", e);
    }
  }

  public void sendHello(Channel channel) {
    byte[] connectionHeader = {'s', 'r', 'p', 'c', 4};
    byte[] buf = new byte[4 + 1 + 1];
    ChannelBuffer buffer = ChannelBuffers.wrappedBuffer(buf);
    buffer.clear();
    buffer.writeBytes(connectionHeader);
    //code for Kerberos AuthMethod enum in HBaseRPC
    buffer.writeByte(81);
    Channels.write(channel, buffer);

    byte[] challengeBytes = null;
    if(saslClient.hasInitialResponse()) {
      challengeBytes = processChallenge(new byte[0]);
    }
    if(challengeBytes != null) {
      buf = new byte[4 + challengeBytes.length];
      buffer = ChannelBuffers.wrappedBuffer(buf);
      buffer.clear();
      buffer.writeInt(challengeBytes.length);
      buffer.writeBytes(challengeBytes);
      Channels.write(channel, buffer);
    }
  }

  public boolean handleResponse(ChannelBuffer buf, Channel chan) {
    final int readIdx = buf.readerIndex();
    final int rpcid = buf.readInt();
    LOG.debug(String.format("rpcid: %d", rpcid));
    if(rpcid == SASL_RPC_ID) {
        //read rpc state
        int state = buf.readInt();
        //0 is success
        LOG.debug("Got SASL RPC state=" + state);
        if(state != 0) {
          return false;
        }

        if(!saslCompleted) {
          int len = buf.readInt();
          LOG.debug("handleSaslResponse:Got len="+len);

          final byte[] b = buf.readBytes(len).array();
          byte[] challengeBytes = processChallenge(b);

          if(challengeBytes != null) {
            byte[] outBytes = new byte[4 + challengeBytes.length];
            ChannelBuffer outBuffer = ChannelBuffers.wrappedBuffer(outBytes);
            outBuffer.clear();
            outBuffer.writeInt(challengeBytes.length);
            outBuffer.writeBytes(challengeBytes);
            LOG.debug("-->handleSaslResponse:sending: "+Bytes.pretty(challengeBytes));
            Channels.write(chan, outBuffer);
          }
          if(saslClient.isComplete()) {
            sendRPCHeader(chan);
            regionClient.sendVersion(chan);
          }
          saslCompleted = challengeBytes == null;
          if(!saslCompleted) {
            return true;
          }
        } else {
          throw new IllegalStateException(
              "SASL handshake complete but still receiving SASL messages");
        }
    } else {
      buf.readerIndex(readIdx);
    }
    return false;
  }

  private byte[] processChallenge(final byte[] b) {
    try {
      return Subject.doAs(clientLogin.getSubject(),
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
  }

  private void sendRPCHeader(Channel channel) {
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
    LOG.debug("-->handleSaslResponse:sending: "+Bytes.pretty(outBuffer));
    Channels.write(channel, outBuffer);
  }

  @Override
  public void operationComplete(ChannelFuture channelFuture) throws Exception {
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

  public static boolean isHBaseSecurityEnabled() {
    return Boolean.valueOf(System.getProperty(SECURITY_AUTHENTICATION_KEY, "kerberos"));
  }
}
