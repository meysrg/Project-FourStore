<?php

namespace Tools;

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;


class RSA_Transaction
{
    public static $algorithm = 'aes-128-cbc';
    public $dbconn;
    public $message;
    public $signaiv;
    public $encryption_key;

    public function __construct($message = null, $signaiv = null, $encryption_key = null)
    {
        $this->message = $message;
        $this->signaiv = $signaiv;
        $this->encryption_key = $encryption_key;
        $this->dbconn = mysqli_connect("localhost", "root", "", "electricks");
    }

    public function setMessage($message)
    {
        $this->message = $message;
    }

    public function setSignaiv($signaiv)
    {
        $this->signaiv = $signaiv;
    }

    public function setEncryption($encryption_key)
    {
        $this->encryption_key = $encryption_key;
    }

    private function encryptMessage($message)
    {
        $cipher = "aes-128-cbc";
        //Generate a 128-bit encryption key 
        $encryption_key = openssl_random_pseudo_bytes(32);
        // Generate an initialization vector 
        $iv_size = openssl_cipher_iv_length($cipher);
        $iv = openssl_random_pseudo_bytes($iv_size);
        $data = $message;
        $encrypted_data = openssl_encrypt($data, $cipher, $encryption_key, 0, $iv);
        return [
            "encrypted_data" => $encrypted_data,
            "encryption_key" => $encryption_key,
            "iv" => base64_encode($iv),
        ];
    }

    public function makeRSA()
    {
        $key = RSA::createKey();
        $public = $key->getPublicKey()->toString("PKCS1");
        $private = $key->toString("PKCS1");
        $encryptedMessageData = $this->encryptMessage($this->message);
        $signature = $key->sign($this->message);
        $sgivnat = $encryptedMessageData['iv'] . "," . base64_encode($signature);
        return [
            'pblc_ky' => $public,
            'prvt_ky' => $private,
            'encrypt_ky' => base64_encode($encryptedMessageData['encryption_key']),
            'msg_crpt' => $encryptedMessageData['encrypted_data'],
            'sgivnat' => $sgivnat,
        ];
    }

    public function decrypt($encrypted_data)
    {
        $decrypted_data = openssl_decrypt($encrypted_data, $this->algorithm, $this->encryption_key, 0, $this->iv);
        return $decrypted_data;
    }

    public function verify($data)
    {
        $load_private = PublicKeyLoader::loadPrivateKey($data['private']);
        $signature = base64_decode(explode(',', $this->signaiv)[1]);
        $iv = base64_decode(explode(',', $this->signaiv)[0]);
        $decrypted_data = openssl_decrypt($data['cipher'], 'aes-128-cbc', base64_decode($this->encryption_key), 0, $iv);
        $order_id = $data['order_id'];
        $result = $load_private->getPublicKey()->verify($decrypted_data, $signature) ?
            'valid signature' :
            'invalid signature';

        if ($result == "valid signature") {
            $query = "UPDATE `order` SET status='Accept' WHERE order_id = $order_id";
            $result = mysqli_query($this->dbconn, $query);
            $this->sendReceipt($order_id);
            header('Location: orders.php');
        }
    }

    public function sendReceipt($order_id)
    {
        $query1 = mysqli_query($this->dbconn, "SELECT * FROM `order` WHERE order_id = $order_id"); // 
        $res1 = mysqli_fetch_array($query1);
        $id = $res1['user_id'];
        $query = mysqli_query($this->dbconn, "SELECT * FROM `users` WHERE user_id = $id"); // 
        $res = mysqli_fetch_array($query);

        $email_user = $res['email'];
        $mail = new PHPMailer(true);
        try {

            //Server settings
            $mail->SMTPDebug = SMTP::DEBUG_SERVER; //SMTP::DEBUG_SERVER                      //Enable verbose debug output
            $mail->isSMTP();                                            //Send using SMTP
            $mail->Host       = 'smtp.gmail.com';                     //Set the SMTP server to send through
            $mail->SMTPAuth   = true;                                   //Enable SMTP authentication
            $mail->Username   = 'jerryandrianto22@gmail.com';                     //SMTP username
            $mail->Password   = 'iaiumxiwygdnvfkg';                               //SMTP password
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;            //Enable implicit TLS encryption
            $mail->Port       = 587;                                    //TCP port to connect to; use 587 if you have set `SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS`

            //Recipients
            $mail->setFrom('jerryandrianto22@gmail.com', 'Admin');
            $mail->addAddress($email_user);
            //Content
            $mail->isHTML(true);                                  //Set email format to HTML
            $mail->Subject = 'Kode OTP Electric Shop';
            $mail->Body    =  $this->receiptBody($res, $res1);

            $mail->send();
            echo 'Message has been sent';
        } catch (Exception $e) {
            die($e);
            echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
        }
    }

    public function receiptBody($res, $order)
    {
        $header = '<!DOCTYPE html>
        <html>
        
        <head>
        
            <meta charset="utf-8">
            <meta http-equiv="x-ua-compatible" content="ie=edge">
            <title>Email Receipt</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style type="text/css">
                /**
           * Google webfonts. Recommended to include the .woff version for cross-client compatibility.
           */
                @media screen {
                    @font-face {
                        font-family: "Source Sans Pro";
                        font-style: normal;
                        font-weight: 400;
                        src: local("Source Sans Pro Regular"), local("SourceSansPro-Regular"), url(https://fonts.gstatic.com/s/sourcesanspro/v10/ODelI1aHBYDBqgeIAH2zlBM0YzuT7MdOe03otPbuUS0.woff) format("woff");
                    }
        
                    @font-face {
                        font-family: "Source Sans Pro";
                        font-style: normal;
                        font-weight: 700;
                        src: local("Source Sans Pro Bold"), local("SourceSansPro-Bold"), url(https://fonts.gstatic.com/s/sourcesanspro/v10/toadOcfmlt9b38dHJxOBGFkQc6VGVFSmCnC_l7QZG60.woff) format("woff");
                    }
                }
        
                /**
           * Avoid browser level font resizing.
           * 1. Windows Mobile
           * 2. iOS / OSX
           */
                body,
                table,
                td,
                a {
                    padding: 35px;
                    -ms-text-size-adjust: 100%;
                    /* 1 */
                    -webkit-text-size-adjust: 100%;
                    /* 2 */
                }
        
                /**
           * Remove extra space added to tables and cells in Outlook.
           */
                table,
                td {
                    mso-table-rspace: 0pt;
                    mso-table-lspace: 0pt;
                }
        
                /**
           * Better fluid images in Internet Explorer.
           */
                img {
                    -ms-interpolation-mode: bicubic;
                }
        
                /**
           * Remove blue links for iOS devices.
           */
                a[x-apple-data-detectors] {
                    font-family: inherit !important;
                    font-size: inherit !important;
                    font-weight: inherit !important;
                    line-height: inherit !important;
                    color: inherit !important;
                    text-decoration: none !important;
                }
        
                /**
           * Fix centering issues in Android 4.4.
           */
                div[style*="margin: 16px 0;"] {
                    margin: 0 !important;
                }
        
                body {
                    width: 100% !important;
                    height: 100% !important;
                    padding: 0 !important;
                    margin: 0 !important;
                }
        
                /**
           * Collapse table borders to avoid space between cells.
           */
                table {
                    border-collapse: collapse !important;
                }
        
                a {
                    color: #1a82e2;
                }
        
                img {
                    height: auto;
                    line-height: 100%;
                    text-decoration: none;
                    border: 0;
                    outline: none;
                }
            </style>
        
        </head>
        
        <body style="background-color: #D2C7BA;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                    <td align="center" bgcolor="#D2C7BA">
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                            <tr>
                                <td align="center" valign="top" style="padding: 36px 24px;">
                                    ELECTRICS STORE
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td align="center" bgcolor="#D2C7BA">
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                            <tr>
                                <td align="left" bgcolor="#ffffff" style="padding: 36px 24px 0; font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; border-top: 3px solid #d4dadf;">
                                    <h1 style="margin: 0; font-size: 32px; font-weight: 700; letter-spacing: -1px; line-height: 48px;">Thank you for your order! <br>' . $res['firstname'] . ' ' . $res['middlename'] . ' ' . $res['lastname'] . '</h1>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
                <tr>
                    <td align="center" bgcolor="#D2C7BA">
                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                            <tr>
                                <td align="left" bgcolor="#ffffff" style="padding: 24px; font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;">
                                    <p style="margin: 0;">Here is a summary of your recent order. If you have any questions or concerns about your order, please <a href="https://sendgrid.com">contact us</a>.</p>
                                </td>
                            </tr>
                            <tr>
                                <td align="left" bgcolor="#ffffff" style="padding: 24px; font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;">
                                    <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                    <tr>
                  <td align="left" bgcolor="#D2C7BA" width="75%" style="padding: 12px;font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;"><strong>Order #</strong></td>
                  <td align="left" bgcolor="#D2C7BA" width="25%" style="padding: 12px;font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;"><strong>0000224</strong></td>
                </tr>';

        $user_id = $res['user_id'];
        $order_id = $order['order_id'];
        $query = mysqli_query($this->dbconn, "SELECT * FROM `order` WHERE user_id='$user_id' and order_id='$order_id'") or die($this->dbconn->error);
        $tbody = '';

        while ($row = mysqli_fetch_array($query)) {
            // die(print("<pre>" . print_r($row, true) . "</pre>"));
            $prod_price = $row['totalprice'];
            $tax = $row['tax'];
            $shipping_address = $row['shipping_add'];
            $tbody .= '
        <tr>
            <td align="left" width="75%" style="padding: 6px 12px;font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;">Shipping Address</td>
            <td align="left" width="25%" style="padding: 6px 12px;font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;">' . $shipping_address . '</td>
        </tr>
        <tr>
            <td align="left" width="75%" style="padding: 6px 12px;font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;">Sales Tax</td>
            <td align="left" width="25%" style="padding: 6px 12px;font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;"> $' . $tax . ' </td>
        </tr>
        <tr>
            <td align="left" width="75%" style="padding: 12px; font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px; border-top: 2px dashed #D2C7BA; border-bottom: 2px dashed #D2C7BA;"><strong>Total</strong></td>
            <td align="left" width="25%" style="padding: 12px; font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px; border-top: 2px dashed #D2C7BA; border-bottom: 2px dashed #D2C7BA;"><strong>$' . $prod_price . '</strong></td>
        </tr>
                ';
        }

        $footer = '
        </table>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td align="center" bgcolor="#D2C7BA" style="padding: 24px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 600px;">
                    <tr>
                        <td align="center" bgcolor="#D2C7BA" style="padding: 12px 24px; font-family: "Source Sans Pro", Helvetica, Arial, sans-serif; font-size: 14px; line-height: 20px; color: #666;">
                            <p style="margin: 0;">You received this email because we received a request for [type_of_action] for your account. If you didn"t request [type_of_action] you can safely delete this email.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>

</body>

</html>';
        return $header . $tbody . $footer;
    }
}