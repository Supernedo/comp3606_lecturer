package com.example.comp3606_a1_lecturer.network

import android.util.Log
import com.google.gson.Gson
import com.example.comp3606_a1_lecturer.models.ContentModel
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.text.Charsets.UTF_8
import kotlin.concurrent.thread

import java.security.MessageDigest
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.SecretKey
import javax.crypto.Cipher
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

class Server(private val iFaceImpl:NetworkMessageInterface) {
    companion object {
        const val PORT: Int = 9999
    }

    private val svrSocket: ServerSocket = ServerSocket(PORT, 0, InetAddress.getByName("192.168.49.1"))
    private val clientMap: HashMap<String, Socket> = HashMap()

    private var studentID = ""
    private var R = ""

    fun ByteArray.toHex() = joinToString(separator = "") { byte -> "%02x".format(byte) }

    fun getFirstNChars(str: String, n:Int) = str.substring(0,n)

    private fun hashStrSha256(str: String): String{
        val algorithm = "SHA-256"
        val hashedString = MessageDigest.getInstance(algorithm).digest(str.toByteArray(UTF_8))
        return hashedString.toHex()
    }

    private fun generateAESKey(seed: String): SecretKeySpec {
        val first32Chars = getFirstNChars(seed,32)
        val secretKey = SecretKeySpec(first32Chars.toByteArray(), "AES")
        return secretKey
    }

    private fun generateIV(seed: String): IvParameterSpec {
        val first16Chars = getFirstNChars(seed, 16)
        return IvParameterSpec(first16Chars.toByteArray())
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun decryptMessage(encryptedText: String, aesKey: SecretKey, aesIv: IvParameterSpec):String{
        val textToDecrypt = Base64.Default.decode(encryptedText)

        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

        cipher.init(Cipher.DECRYPT_MODE, aesKey,aesIv)

        val decrypt = cipher.doFinal(textToDecrypt)
        return String(decrypt)

    }

    private fun isEncryptedMessage(message: String): Boolean {
        if (studentID != "") {
            val strongStudentID = hashStrSha256(studentID)
            val aesKey = generateAESKey(strongStudentID)
            val aesIv = generateIV(strongStudentID)

            val value = decryptMessage(message, aesKey, aesIv)

            if (value == R)
                return true
            else
                close()
        }

        return false
    }

    init {
        thread{
            while(true){
                try{
                    val clientConnectionSocket = svrSocket.accept()
                    Log.e("SERVER", "The server has accepted a connection: ")
                    handleSocket(clientConnectionSocket)

                }catch (e: Exception){
                    Log.e("SERVER", "An error has occurred in the server!")
                    e.printStackTrace()
                }
            }
        }
    }


    private fun handleSocket(socket: Socket){
        socket.inetAddress.hostAddress?.let {
            clientMap[it] = socket
            Log.e("SERVER", "A new connection has been detected!")
            thread {
                val clientReader = socket.inputStream.bufferedReader()
                val clientWriter = socket.outputStream.bufferedWriter()
                var receivedJson: String?
                var hasSentR = false

                val classIDsRange = (816000000..816000008).toList()
                val classIDs = classIDsRange.toMutableList()

                classIDs.add(816117992)

                while(socket.isConnected){
                    try{
                        receivedJson = clientReader.readLine()
                        if (receivedJson!= null){
                            Log.e("SERVER", "Received a message from client $it")
                            val clientContent = Gson().fromJson(receivedJson, ContentModel::class.java)
                            if (clientContent.message.startsWith("816")){
                                studentID = clientContent.message.toString()

                                if (!classIDs.contains(studentID.toInt())){
                                    Log.e("SERVER", "ID: ${clientContent.message}, does not belong to this class")
                                    close()
                                    break
                                }
                            }

                            if (hasSentR) {
                                // Check if the received message is a reply
                                if (isEncryptedMessage(clientContent.message)) {
                                    Log.d("SERVER", "Received reply from client: ${clientContent.message}")
                                }
                            } else {
                                val randomNumber = ((0..100).random()).toString()
                                val rObj = ContentModel(randomNumber, "192.168.49.1")

                                val rStr = Gson().toJson(rObj)
                                clientWriter.write("$rStr\n")
                                clientWriter.flush()
                                hasSentR = true // Set the flag to true after sending R

                                // Swap IPs for alignment if needed
                                val tmpIp = clientContent.senderIp
                                clientContent.senderIp = rObj.senderIp
                                rObj.senderIp = tmpIp

                                iFaceImpl.onContent(clientContent)
                                iFaceImpl.onContent(rObj)
                            }
                        }
                    } catch (e: Exception){
                        Log.e("SERVER", "An error has occurred with the client $it")
                        e.printStackTrace()
                    }
                }
            }
        }
    }

    fun close(){
        svrSocket.close()
        clientMap.clear()
    }
}