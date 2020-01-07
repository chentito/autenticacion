<?php
/* Autenticacion al servicio de descarga masiva SAT
 * @Autor Mexagon.net / Carlos Reyes
 * @Fecha Diciembre 2018
 */
//include_once '/home/virtual/facturacion-mx/html/cfdi/lib/classConMySQL.php';
ini_set("display_errors","1");

class SATAuth {
    /*
     * Atributos Publicos
     */
    public $response    = '';
    public $error       = '';
    public $codigo      = '';
    public $mensaje     = '';
    public $token       = '';
    public $created     = '';
    public $expires     = '';
    public $faultcode   = '';
    public $faultstring = '';
    public $password    = "xxxxxxxx";
    public $archivoCer  = "xxxxxxxx.cer";
    public $archivoKey  = "xxxxxxxx.key";
    public $database    = "cfd_mexagon_resc840317j72";

    /*
     * Atrubtos privados
     */
    private $urlSAT         = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc';
    private $msjAuth        = '';
    private $fechaCrea      = '';
    private $fechaExpira    = '';
    private $certificadoB64 = '';
    private $sello          = '';
    private $digest         = '';
    private $idty           = '';
    private $temps          = array();
    private $curl           = '';
    private $signedInfo     = '';
    private $timeStamp      = '';
    private $dbCon          = null;
    private $diffMinServSat = 360;

    /*********************************
     *      METODOS PUBLICOS
     *********************************/
    
    /* Constructor */
    public function __construct() {
        $this->idty = $this->idty();
        //$this->dbCon = new classConMySQL();
    }

    /* Destructor */
    public function __destruct() {
        foreach( $this->temps AS $temp ) {
            //unlink( $temp );
        }
    }

    /* Metodo que verifica la disponibilidad del token */
    public function obtieneToken() {
        if( $this->buscaToken() ) {
                return $this->token;
            } else {
                return $this->autenticacion();
        }
    }

    /*********************************
     *      METODOS PRIVADOS
     *********************************/
    
    /* Busca token vigente en la base de datos */
    private function buscaToken() {return false;
        $this->dbCon->setDabataseClient( $this->database );
        $fecha = date( 'Y-m-d H:i:s' , strtotime( '+ ' . $this->diffMinServSat . ' minute' ) );
        $sql   = " SELECT token FROM ".$this->database.".cfd_tokenSAT WHERE created >= '" . $fecha . "' AND expires < '" . $fecha . "' ";
        $rs    = $this->dbCon->traedatosmysql( $sql );
        if( $rs && !$rs->EOF ) {
            $this->token = $rs->fields[ 'token' ];
            return true;
        } else {
            return false;
        }
    }
    
    /* Metodo que invoca la autenticacion */
    private function autenticacion() {
        $this->generaInformacionAutenticacion();
        try {
                $this->mensajeCurl();
            } catch ( Exception $e ) {
                $this->error = $e->getMessage();
                echo $this->error;
        }
        return $this->token;
    }

    /* Mensaje CURl para la comunicacion con el SAT */
    private function mensajeCurl() {
        $this->curl = curl_init();
        $this->armaMensajeSOAP();
        curl_setopt_array( $this->curl , array (
            CURLOPT_URL            => $this->urlSAT,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST  => 'POST',
            CURLOPT_POSTFIELDS     => $this->msjAuth,
            CURLOPT_HTTPHEADER     => array (
                                        "Accept: text/xml",
                                        "Content-Type: text/xml; charset=utf-8",
                                        "cache-control: no-cache",
                                        "SOAPAction: http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica"
                                    )
        ));
        $this->response = curl_exec( $this->curl );
        $this->error    = curl_error( $this->curl );
        $this->codigo   = curl_getinfo( $this->curl , CURLINFO_HTTP_CODE );
        curl_close( $this->curl );

        if ( $this->error ) {
            throw new Exception( "Error en la comunicacion CURL" );
        } else {
            $this->obtieneDatos();
            if( $this->codigo != 200 ) {
                    throw new Exception( "Error codigo: " . $this->codigo . " Con el mensaje: " . $this->response );
                } else {
                    trigger_error($this->codigo);
            }
        }
    }

    /* Estructura timestamp para crear el digest value */
    private function creaTimeStamp() {
        $this->timeStamp = '<u:Timestamp xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="'.$this->idty[ 1 ].'">'
                         . '<u:Created>'.$this->fechaCrea.'</u:Created>'
                         . '<u:Expires>'.$this->fechaExpira.'</u:Expires>'
                         . '</u:Timestamp>';
        $digestValue  = sha1( $this->timeStamp , true );
        $this->digest = base64_encode( $digestValue );
    }

    /* Estructura signed info para crear el sello digital */
    private function sello() {
        $this->signedInfo = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
                          . '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
                          . '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
                          . '<Reference URI="#'.$this->idty[ 1 ].'">'
                          . '<Transforms>'
                          . '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
                          . '</Transforms>'
                          . '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
                          . '<DigestValue>'.$this->digest.'</DigestValue>'
                          . '</Reference>'
                          . '</SignedInfo>';
        $xml = new DOMDocument( "1.0", "ISO-8859-15" );
        $xml->loadXML( $this->signedInfo );
        $this->sello = $this->llavePrivada( $xml->C14N() );
    }

    /* Estructura del mensaje requerido por el SAT para la autenticacion */
    private function armaMensajeSOAP() {
        $this->creaTimeStamp();
        $this->sello();
        $this->msjAuth  = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                        . 'xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
                        . '<s:Header>'
                        . '<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">';
        $this->msjAuth .= str_replace( ' xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"' , '' , $this->timeStamp );
        $this->msjAuth .= '<o:BinarySecurityToken u:Id="'.$this->idty[ 0 ].'" '
                            . 'ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" '
                            . 'EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
                            . $this->certificadoB64
                        . '</o:BinarySecurityToken>';
        $this->msjAuth .= '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">';
        $this->msjAuth .= str_replace( ' xmlns="http://www.w3.org/2000/09/xmldsig#"' , '' , $this->signedInfo );
        $this->msjAuth .= '<SignatureValue>' . $this->sello . '</SignatureValue>'
                        . '<KeyInfo>'
                            . '<o:SecurityTokenReference>'
                                . '<o:Reference '
                                . 'ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" '
                                . 'URI="#'.$this->idty[ 0 ].'"/>'
                            . '</o:SecurityTokenReference>'
                        . '</KeyInfo>'
                        . '</Signature>'
                        . '</o:Security>'
                        . '</s:Header>'
                        . '<s:Body>'
                            . '<Autentica xmlns="http://DescargaMasivaTerceros.gob.mx"/>'
                        . '</s:Body>'
                        . '</s:Envelope>';
    }

    /* Inicializacion de datos */
    private function generaInformacionAutenticacion() {
        $this->fechaCrea      = date( 'Y-m-d' ) . 'T' . date( 'H:i:s' , strtotime( '+ ' . $this->diffMinServSat.' minute' ) ) . '.117Z';
        $this->fechaExpira    = date( 'Y-m-d' ) . 'T' . date( 'H:i:s' , strtotime( '+ ' . ( $this->diffMinServSat + 5 ) . ' minute' ) ) . '.117Z';
        $this->certificadoB64 = $this->obtieneCertificado();
    }

    /* Obtencion del certificado e.firma en base 64 */
    private function obtieneCertificado() {
        $certificado = base64_encode( file_get_contents( $this->archivoCer ) );
        return $certificado;
    }

    /* Firmado y creacion de sello digital */
    private function llavePrivada( $nodo ) {
        $crypttext     = '';
        exec( '/usr/bin/openssl pkcs8 -inform DER -in ' . $this->archivoKey . ' -out ' . $this->archivoKey . '.pem -passin pass:' . $this->password );
        $this->temps[] = $this->archivoKey . '.pem';
        $pkeyid        = openssl_get_privatekey( file_get_contents( $this->archivoKey . '.pem' ) );
        openssl_sign( $nodo , $crypttext , $pkeyid , OPENSSL_ALGO_SHA1 );
        openssl_free_key( $pkeyid );
        return base64_encode( $crypttext );
    }

    /* Creacion de identificadores */
    private function idty() {
        return array( rand( 11111 , 99999 ) , rand( 11111 , 99999 ) );
    }

    /* Metodo que obtiene token del responde */
    private function obtieneDatos() {
        $dom = new DOMDocument();
        $dom->loadXML( $this->response );

        if( $dom->getElementsByTagName( 'faultcode' )->length > 0 ) {
                $this->faultstring = utf8_decode( $dom->getElementsByTagName( 'faultstring' )->item( 0 )->nodeValue );
                $this->faultcode   = utf8_decode( $dom->getElementsByTagName( 'faultcode' )->item( 0 )->nodeValue );
            } else {
                $namespaceURI  = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
                $this->mensaje = 'Exito';
                $this->token   = utf8_decode( $dom->getElementsByTagName( 'AutenticaResult' )->item( 0 )->nodeValue );
                $this->created = utf8_decode( $dom->getElementsByTagNameNS( $namespaceURI , 'Created' )->item( 0 )->nodeValue );
                $this->expires = utf8_decode( $dom->getElementsByTagNameNS( $namespaceURI , 'Expires' )->item( 0 )->nodeValue );
                $this->guardaToken();
        }
    }

    /* Guarda los datos del token */
    private function guardaToken() {return true;
        $this->dbCon->setDabataseClient( $this->database );
        $sql = " INSERT INTO ".$this->database.".cfd_tokenSAT (created, expires, token)"
             . " VALUES ('".$this->created."', '".$this->expires."', '".$this->token."');";
        $this->dbCon->traedatosmysql( $sql );
    }

}

/* Ejecucion del proceso */
$auth = new SATAuth();
$token = $auth->obtieneToken();

echo $token."\n";
