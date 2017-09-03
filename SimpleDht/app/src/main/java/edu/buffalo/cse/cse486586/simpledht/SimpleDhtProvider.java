package edu.buffalo.cse.cse486586.simpledht;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDhtProvider extends ContentProvider {
    static final String TAG = SimpleDhtProvider.class.getSimpleName();

    static final String rport0 = "11108";
    static final String rport1 = "11112";
    static final String rport2 = "11116";
    static final String rport3 = "11120";
    static final String rport4 = "11124";
    String succ;
    String pred;
    static final int server = 10000;
    static final String leader = "5554";
    String selfID;
    int selfPort = 0;
    private static final String KEY_FIELD = "key";
    private static final String VALUE_FIELD = "value";
    int count = 0;
    List<String> portList = new ArrayList<String>();
    List<String> nodes = new ArrayList<String>();
    TreeMap<String, String> tableAll = new TreeMap();
    Map<String, String> nodeMap = new HashMap<String, String>();
    boolean alone = false;


    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub

        String query = selection;

        if(alone){
            if(query.contains("@")||query.contains("*")){

                String[] fileArray = getContext().getFilesDir().list();
                for (String file : fileArray) {
//                    try {
                        getContext().deleteFile(file);
//                    }
                    }

            }
            else{

                getContext().deleteFile(query);

            }
        }
        else{
            if(query.contains("@")){

                String[] fileArray = getContext().getFilesDir().list();
                for (String file : fileArray) {
//                    try {
                    getContext().deleteFile(file);
                    }

            }
            else if(query.contains("*")){
                String[] fileArray = getContext().getFilesDir().list();
                for (String file : fileArray) {
//                    try {
                    getContext().deleteFile(file);
                }

                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "DELETEALL");


            }
            else{
                String keyHash = null;
                try {
                    keyHash = genHash(query);

                String pos = getPos(keyHash);
                String avd = tableAll.get(pos);

                if(avd.equals(selfID)){

                    getContext().deleteFile(query);


                }
                    else{

                    String msgToDel = query+":"+avd;
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "DELETEREDIR",msgToDel);


                }



                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }

            }



            }




        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub

        String key = values.getAsString(KEY_FIELD);
        String val = values.getAsString(VALUE_FIELD);

        if (!alone){
            try {
                String keyHash = genHash(key);

                String keyPos = getPos(keyHash);
                System.out.println("keyPos is "+keyPos+" keyHash is "+keyHash);
                System.out.println("Current nodeMap is "+nodeMap);
                String avdPos = tableAll.get(keyPos);

                System.out.println("Got AVD pos " + avdPos + " for message " + key);

                if (avdPos.equals(selfID)) {
                    FileOutputStream outputStream;
                    String msg = values.get("value").toString();

                    try {
                        outputStream = getContext().openFileOutput(key, Context.MODE_PRIVATE);
                        outputStream.write(val.getBytes());
                        outputStream.close();
                    } catch (Exception e) {
                        //  Log.e(TAG, "File write failed");
                    }

                    System.out.println("Wrote in " + selfID + " message " + key);
                    Log.v("insert", values.toString());
                    return uri;

                } else {

                    String message = key + ":" + val + ":" + avdPos;
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "INSERTREDIR", message);
                    System.out.println("Sent Insert Redir from " + selfID + " to " + avdPos + " for "+key);
                }
                return uri;

            } catch (Exception e) {
                e.printStackTrace();
            }
    }
        else {
            FileOutputStream outputStream;
            String msg = values.get("value").toString();

            try {
                outputStream = getContext().openFileOutput(key, Context.MODE_PRIVATE);
                outputStream.write(val.getBytes());
                outputStream.close();
            } catch (Exception e) {
                //  Log.e(TAG, "File write failed");
            }


            Log.v("insert", values.toString());
            return uri;
        }



        return null;

    }


    public String getPos(String s) {
        //https://docs.oracle.com/javase/7/docs/api/java/util/TreeMap.html

        String result;
        //Check if keyHash is greater than max AVD hash present in Ring
        if (s.compareTo(tableAll.lastKey()) > 0) {
            result = tableAll.firstKey();
            System.out.println("Returning getPos firstKey" + result);

            return result;

        } else {
            //Return hash of AVD having least hash greater than or equal to the given key, or null if there is no such key.
            result = tableAll.ceilingKey(s);
            System.out.println("Returning getPos ceilingKey" + result);
            return result;
        }


    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub
//        portList.add(rport0);
//        portList.add(rport1);
//        portList.add(rport2);
//        portList.add(rport3);
//        portList.add(rport4);
        TelephonyManager tel = (TelephonyManager) getContext().getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        String myPort = String.valueOf((Integer.parseInt(portStr) * 2));
        selfPort = Integer.parseInt(myPort);
        selfID = Integer.toString(selfPort / 2);
        alone = true;

        if (selfID.equals(leader)) {
            try {
                nodes.add(genHash(selfID));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            succ = selfID;
            pred = selfID;
            try {
                tableAll.put(genHash(selfID), selfID);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        try {
            nodeMap.put(genHash(selfID), selfID);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            /*
             * Create a server socket as well as a thread (AsyncTask) that listens on the server
             * port.
             *
             * AsyncTask is a simplified thread construct that Android provides. Please make sure
             * you know how it works by reading
             * http://developer.android.com/reference/android/os/AsyncTask.html
             */
            ServerSocket serverSocket = new ServerSocket(server);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            /*
             * Log is a good way to debug your code. LogCat prints out all the messages that
             * Log class writes.
             *
             * Please read http://developer.android.com/tools/debugging/debugging-projects.html
             * and http://developer.android.com/tools/debugging/debugging-log.html
             * for more information on debugging.
             */
            Log.e(TAG, "Can't create a ServerSocket");
//            return;
        }

        if (!(selfID.equals(leader))) {
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "JOIN_REQ", selfID);
            System.out.println("Sent JOIN REQUEST to Leader from " + selfID);
            return true;
        }


        return false;
    }


    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {

        //http://instinctcoder.com/android-studio-asynctask-return-value-to-caller/


        MatrixCursor cursor = new MatrixCursor(new String[]{"key","value"});

        String query = selection;
        System.out.println("Received query "+selection+" at "+selfID);

        if(alone) {
            if (query.equals("\"@\"") || query.equals("@") || query.equals("\"*\"") || query.equals("*")) {

                String[] fileArray = getContext().getFilesDir().list();
                for (String file : fileArray) {
                    try {
//                        FileInputStream fis = getContext().openFileInput(file);
//                        if(fis!=null){
//
//                        }
                        BufferedReader br = new BufferedReader(new InputStreamReader(getContext().openFileInput(file)));
                        String res;
                        if ((res = br.readLine()) != null) {
                            cursor.addRow(new Object[]{file, res});
                        }


                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
                return cursor;
            } else {
                try {
//                        FileInputStream fis = getContext().openFileInput(file);
//                        if(fis!=null){
//
//                        }
                    BufferedReader br = new BufferedReader(new InputStreamReader(getContext().openFileInput(query)));
                    String res;
                    if ((res = br.readLine()) != null) {
                        cursor.addRow(new Object[]{query, res});
                    }


                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                return cursor;

            }
        }
        else{

            if (query.equals("\"@\"") || query.equals("@")) {

                System.out.println("Entering local @ query at "+selfID);
                String[] fileArray = getContext().getFilesDir().list();
                for (String file : fileArray) {
                    try {
//                        FileInputStream fis = getContext().openFileInput(file);
//                        if(fis!=null){
//
//                        }
                        BufferedReader br = new BufferedReader(new InputStreamReader(getContext().openFileInput(file)));
                        String res;
                        if ((res = br.readLine()) != null) {
                            cursor.addRow(new Object[]{file, res});
                        }


                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }

                }
                return cursor;

            }

            else if(query.equals("\"*\"") || query.equals("*")){
                try {
                    MatrixCursor resall =   new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "QUERYALL").get();


                    return resall;

                } catch (InterruptedException e) {
                    e.printStackTrace();
                } catch (ExecutionException e) {
                    e.printStackTrace();
                }


            }


            else{
                try {
                    String keyHash = genHash(query);
                    String pos = getPos(keyHash);
                    String avd = tableAll.get(pos);

                    if(avd.equals(selfID))
                    {
                        BufferedReader br = new BufferedReader(new InputStreamReader(getContext().openFileInput(query)));
                        String res;
                        if ((res = br.readLine()) != null) {
                            cursor.addRow(new Object[]{query, res});
                            return cursor;
                        }
                    }
                    else
                    {
                        String message = query+":"+selfID+":"+avd;

                      MatrixCursor res =   new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "QUERYREDIR", message).get();
                        return res;


                    }

                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } catch (ExecutionException e) {
                    e.printStackTrace();
                }


            }


            }





        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }


    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }


    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];

            /*
             * TODO: Fill in your server code that receives messages and passes them
             * to onProgressUpdate().
             */

//            try {
            //Open a server socket to listen to incoming messages
            while (true) {
                try {
                    Socket s = serverSocket.accept();
//                    ObjectInputStream ois = new ObjectInputStream(s.getInputStream());

                    InputStreamReader is = null;

                    is = new InputStreamReader(s.getInputStream());
                    BufferedReader br = new BufferedReader(is);
                    String msg;
                    if ((msg = br.readLine()) != null) {

                        String[] msgAr = msg.split(":");
                        if (msgAr[0].equals("JOIN_REQ")) {
                            System.out.println("Received Join Req from " + msgAr[1]);

                            nodes.add(genHash(msgAr[1]));
                            alone = false;
                            nodeMap.put(genHash(msgAr[1]), msgAr[1]);
                            tableAll.put(genHash(msgAr[1]), msgAr[1]);
                            Thread.sleep(100);
//                            if(nodes.size()==5)
                            relayToNodes();
                        }
                        if (msgAr[0].equals("UPDATE")) {
                            alone=false;

                            succ = msgAr[1];
                            pred = msgAr[2];
                            String line = br.readLine();
                            int count = Integer.parseInt(line);
                            System.out.println("Received Succ and Pred at " + selfID + " Successor is " + succ + " Pred is " + pred);
//                            while(( line = br.readLine())!=null){
                            for (int i = 0; i < count; i++) {
                                line = br.readLine();
                                String[] tab = line.split(":");
                                tableAll.put(tab[0], tab[1]);
                                System.out.println("added to tableall " + tableAll);
                            }
//                            }

                        }

                        if (msgAr[0].equals("INSERT")) {

                            System.out.println("Received INSERT REDIR at "+selfID+" for key "+msgAr[1]);
                            String URL = "content://edu.buffalo.cse.cse486586.simpledht.provider";
                            Uri uri = Uri.parse(URL);
                            ContentValues values = new ContentValues();
                            values.put(KEY_FIELD,msgAr[1]);
                            values.put(VALUE_FIELD,msgAr[2]);
                            insert(uri,values);
//                            Uri newUri = getContentResolver().insert(uri,values);


                        }
                        if (msgAr[0].equals("QUERY")) {

                            System.out.println("Received Query REDIR at "+selfID+" for key "+msgAr[1]);
                            BufferedReader resp = new BufferedReader(new InputStreamReader(getContext().openFileInput(msgAr[1])));
                            String res;
                            if ((res = resp.readLine()) != null) {
                                System.out.println("Successfully queried file");
                                String response = msgAr[1]+":"+res;
                                PrintWriter pw = new PrintWriter(s.getOutputStream(), true);
                                pw.println(response);
                                System.out.println("Sent back response to "+msgAr[2]);
//                                pw.flush();

//                                cursor.addRow(new Object[]{msg, res});
//                                return cursor;
                            }
//                            Uri newUri = getContentResolver().insert(uri,values);


                        }
                        if (msgAr[0].equals("QUERYALL")) {
                            System.out.println("Received Query ALL at "+selfID);

                            PrintWriter pw = new PrintWriter(s.getOutputStream(), true);

                            String[] fileArray = getContext().getFilesDir().list();
                            int count = fileArray.length;
                            pw.println(fileArray.length);
                            System.out.println("Sent count for * as "+count+" from "+selfID);
                            pw.flush();
                            for (String file : fileArray) {
                                try {
//                        FileInputStream fis = getContext().openFileInput(file);
//                        if(fis!=null){
//                        }
                                    BufferedReader br2 = new BufferedReader(new InputStreamReader(getContext().openFileInput(file)));
                                    String res = br2.readLine();
//                                    if ((res = br2.readLine()) != null) {
//                                        cursor.addRow(new Object[]{file, res});
                                        System.out.println("Sending value for * " + file+"  " + res);
                                        pw.println(file+":"+res);
                                        pw.flush();
//                                    }


                                } catch (FileNotFoundException e) {
                                    e.printStackTrace();
                                } catch (IOException e) {
                                    e.printStackTrace();
                                }

                            }

//                            pw.println(response);


                        }

                        if (msgAr[0].equals("DELETEALL"))
                        {

                            String[] fileArray = getContext().getFilesDir().list();
                            for (String file : fileArray) {
//                    try {
                                getContext().deleteFile(file);
                            }


                        }
                        if (msgAr[0].equals("DELETEREDIR")){

                            String key = msgAr[1];
                            getContext().deleteFile(key);


                        }



                    }
//                    if (ois.readObject()!=null){
//                    Msg received = (Msg) ois.readObject();
//                        if(received.type.equals("TABLE")){
//                            tableAll = received.table;
//                            System.out.println("Received TABLE at " + selfID);
//                            System.out.println("Table is " + tableAll);
//                        }
//
//
//                    }

                } catch (IOException e) {
                    e.printStackTrace();
//                        System.out.println("Socket ERROR at port " + s.getPort());
//                        portList.remove(s.getPort());
//                        deadPort = "deadport:"+s.getPort()+":";
//                    Log.e(TAG, "ServerSocket Exception");
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
//             }
            }
//

        }


    }

    public void relayToNodes() {
        Collections.sort(nodes);

        if (nodes.size() > 1) {
            System.out.println("Total Nodes are " + nodes.size());
            System.out.println("Current list is " + nodes);
            System.out.println("Current nodes are " + nodeMap);
            for (int i = 0; i < nodes.size(); i++) {


                String successor;
                String predec;
                String destID;
                destID = nodeMap.get(nodes.get(i));
                if (i == 0) {
                    if (destID.equals("5554")) {
                        succ = nodeMap.get(nodes.get(1));
                        pred = nodeMap.get(nodes.get(nodes.size() - 1));
                        System.out.println("Set self s/p as " + succ + pred);
                        continue;
                    }
                    successor = nodeMap.get(nodes.get(1));
                    predec = nodeMap.get(nodes.get(nodes.size() - 1));
                } else if (i == (nodes.size() - 1)) {
                    if (destID.equals("5554")) {
                        succ = nodeMap.get(nodes.get(0));
                        pred = nodeMap.get(nodes.get(i - 1));
                        System.out.println("Set self s/p as " + succ + pred);
                        continue;
                    }
                    successor = nodeMap.get(nodes.get(0));
                    predec = nodeMap.get(nodes.get(i - 1));

                    System.out.println("i=nodes.size-1 setting " + successor + predec + destID);

                } else {
                    if (destID.equals("5554")) {
                        succ = nodeMap.get(nodes.get(i + 1));
                        pred = nodeMap.get(nodes.get(i - 1));
                        System.out.println("Set self s/p as " + succ + pred);
                        continue;
                    }
                    successor = nodeMap.get(nodes.get(i + 1));
                    predec = nodeMap.get(nodes.get(i - 1));
                    System.out.println("i=other setting " + successor + predec + destID);


                }

                if (!(destID.equals("5554"))) {
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, "UPDATE", successor + ":" + predec + ":" + destID);
                    System.out.println("Sent S/P to " + destID + " Succ is " + successor + " Pred is " + predec);
                }
//                   
            }

        }
    }


    public class Msg implements Serializable {

        String type;
        TreeMap<String, String> table;

    }


    /***
     * ClientTask is an AsyncTask that should send a string over the network.
     * It is created by ClientTask.executeOnExecutor() call whenever OnKeyListener.onKey() detects
     * an enter key press event.
     *
     * @author stevko
     */
    private class ClientTask extends AsyncTask<String, Void, MatrixCursor> {
//https://developer.android.com/reference/android/os/AsyncTask.html
// Changed return type of ClientTask to MatrixCursor so that we return a matrix cursor upon querying
        @Override
//        protected Void doInBackground(String... msgs) {
          protected MatrixCursor doInBackground(String... msgs) {

                String msgRec = msgs[0];
            if (msgRec.contains("JOIN_REQ")) {
                Socket socket = null;
                try {
//                  Thread.sleep(300);
                    do {
                        socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                (Integer.parseInt(leader) * 2));
                    } while (!socket.isConnected());

                    String msgToSend = "JOIN_REQ" + ":" + selfID + ":" + selfPort + ":";

                    PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
                    pw.println(msgToSend);

                    System.out.println("Sent JOIN_REQ to " + leader + " from " + selfID);
//                  pw.close();
//                  socket.close();
//                  try {
                    Thread.sleep(100);
//                  } catch (InterruptedException e) {
//                      e.printStackTrace();
//                  }
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }


            } else if (msgRec.contains("UPDATE")) {

                String msgAr[] = msgs[1].split(":");

                try {
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            (Integer.parseInt(msgAr[2]) * 2));
                    String msgToSend = "UPDATE" + ":" + msgAr[0] + ":" + msgAr[1];

                    PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
                    pw.println(msgToSend);
                    pw.flush();
                    pw.println(tableAll.size());
                    pw.flush();
                    for (String s : tableAll.keySet()) {
                        String msg = s + ":" + tableAll.get(s);
                        pw.println(msg);
                        pw.flush();
                    }
//                  pw.close();
                    System.out.println("Sent UPDATE req to " + Integer.parseInt(msgAr[2]) * 2 + "Succ is " + msgAr[0] + " Pred is " + msgAr[1]);
                    Thread.sleep(100);

//                  socket.close();
//                  try {
//                      Thread.sleep(100);
//                  } catch (InterruptedException e) {
//                      e.printStackTrace();
//                  }
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }


            } else if (msgRec.contains("INSERTREDIR")) {

                String msgAr[] = msgs[1].split(":");

                try {
                    Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            (Integer.parseInt(msgAr[2]) * 2));
                    String msgToSend = "INSERT" + ":" + msgAr[0] + ":" + msgAr[1];

                    PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
                    pw.println(msgToSend);
//                    pw.flush();
//                    pw.println(tableAll.size());
//                    pw.flush();
//                    for (String s : tableAll.keySet()) {
//                        String msg = s + ":" + tableAll.get(s);
//                        pw.println(msg);
//                        pw.flush();
//                    }


                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
            else if (msgRec.contains("QUERYREDIR")) {
                String msgAr[] = msgs[1].split(":");

                try {
                    System.out.println("Trying QUERYREDIR at "+selfID+" to port " + msgAr[2] +" for key " + msgAr[0]);
                    Socket socket = null;
//                    do {
                        socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                (Integer.parseInt(msgAr[2]) * 2));
//                    } while(!socket.isConnected());
                    System.out.println("Socket connected");
                    String rep;

                    String msgToSend = "QUERY" + ":" + msgAr[0] + ":" + msgAr[1];

                    PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
                    pw.println(msgToSend);
//                    pw.flush();
                    System.out.println("Sent QUERYREDIR");
//                    pw.close();
                    Thread.sleep(100);
                    MatrixCursor res = new MatrixCursor(new String[]{"key","value"});
                    InputStreamReader is = new InputStreamReader(socket.getInputStream());
                    BufferedReader br1 = new BufferedReader(is);
                    if ((rep = br1.readLine()) != null)
                    {
                        System.out.println("Response received " + rep);
                        System.out.println("Inside readline Loop with "+ rep);
                        String[] resp = rep.split(":");
                        String out = resp[1];

                        res.addRow(new Object[]{msgAr[0], out});
                    }
                    return res;


                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }

            }
            else if (msgRec.contains("QUERYALL")) {

                //http://stackoverflow.com/questions/5757202/how-would-i-print-all-values-in-a-treemap
                MatrixCursor res = new MatrixCursor(new String[]{"key","value"});

                for(Map.Entry<String,String> entry: tableAll.entrySet()) {
                    String node = entry.getValue();

                    if (node.equals(selfID)) {
                        System.out.println("Entering local @ query at " + selfID);
                        String[] fileArray = getContext().getFilesDir().list();
                        for (String file : fileArray) {
                            try {
//                        FileInputStream fis = getContext().openFileInput(file);
//                        if(fis!=null){
//
//                        }
                                BufferedReader br = new BufferedReader(new InputStreamReader(getContext().openFileInput(file)));
                                String res1;
                                if ((res1 = br.readLine()) != null) {
                                    res.addRow(new Object[]{file, res1});
                                }
                            } catch (FileNotFoundException e) {
                                e.printStackTrace();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }

                        }

                    }

                    else{




                        try {
                            System.out.println("Trying QUERYALL at "+selfID+" to port " + node +" for * ");
                            Socket socket = null;
//                    do {
                            socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    (Integer.parseInt(node) * 2));
//                    } while(!socket.isConnected());
                            System.out.println("Socket connected");
                            String rep;

                            String msgToSend = "QUERYALL";

                            PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
                            pw.println(msgToSend);
//                    pw.flush();
                            System.out.println("Sent QUERYALL");
//                    pw.close();
                            Thread.sleep(100);
//                            MatrixCursor res = new MatrixCursor(new String[]{"key","value"});
                            InputStreamReader is = new InputStreamReader(socket.getInputStream());
                            BufferedReader br1 = new BufferedReader(is);
                            int count = Integer.parseInt(br1.readLine());
                            System.out.println("Received count for QUERYALL " + count);
//                            if ((rep = br1.readLine()) != null)
//                            {
                                String line;
//                                int count = Integer.parseInt(rep);
                                for(int i = 0;i<count;i++) {
                                    line = br1.readLine();

                                    String[] tab = line.split(":");
                                    System.out.println("Adding row to res for "+node+" key is "+tab[0]+" value is "+tab[1]);
                                    res.addRow(new Object[]{tab[0], tab[1]});
                                }
//                                System.out.println("Response received " + rep);
//                                System.out.println("Inside readline Loop with "+ rep);
//                                String[] resp = rep.split(":");
//                                String out = resp[1];

//                                res.addRow(new Object[]{msgAr[0], out});
//                            }
//                            return res;


                        } catch (UnknownHostException e) {
                            e.printStackTrace();
                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }



                    }


                }
                return res;

            }else if (msgRec.contains("DELETEALL")) {



                for(Map.Entry<String,String> entry: tableAll.entrySet()) {
                    String node = entry.getValue();
                    if (node.equals(selfID)) {
                        String[] fileArray = getContext().getFilesDir().list();
                        for (String file : fileArray) {
//                    try {
                            getContext().deleteFile(file);
                        }
                    }
                    else{

                        Socket socket = null;
//                    do {
                        try {
                            socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    (Integer.parseInt(node) * 2));
                            String msgToSend = "DELETEALL";

                            PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
                            pw.println(msgToSend);
                            Thread.sleep(100);



                        } catch (IOException e) {
                            e.printStackTrace();
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }


                    }

                }


            }
            else if (msgRec.contains("DELETEREDIR")) {
                String msgAr[] = msgs[1].split(":");


                Socket socket = null;
//                    do {
                try {
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            (Integer.parseInt(msgAr[1]) * 2));
                    String msgToSend = "DELETEREDIR"+":"+msgAr[0];

                    PrintWriter pw = new PrintWriter(socket.getOutputStream(), true);
                    pw.println(msgToSend);
                    Thread.sleep(100);

                } catch (InterruptedException e) {
                    e.printStackTrace();
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }


            }

                return null;

        }


    }
}






