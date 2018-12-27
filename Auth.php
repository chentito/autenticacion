<?php
/*
 * Clase que realiza la autenticacion con el SAT
 *
 * @Autor Mexagon.net / Carlos Reyes
 * @Fecha Diciembre 2018
 */
 require_once './Utils.php';

 class Auth extends Utils {
    /*
     * Atributos publicos
     */
    public $token   = '';
    public $error   = '';
    public $codigo  = '';
    public $mensaje = '';

    /* 
     * Atributos privados
     */
    private $urlSAT = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc';
    private $ids = array();
    private $msjAuth = array();
    private $timeStamp = '';
    private $digest = '';
    private $signedInfo = '';
    private $fechaCrea = '';
    private $fechaExpira = '';
    private $database = '';

    /*********************************
     *      METODOS PUBLICOS
     *********************************/

    /* Constructor */
    public function __construct() {
        $this->database = 'cfd_mexagon_resc840317j72';
    }

    /* Destructor */
    public function __destruct() {
        //$this->gc();
    }

    /* Metodo que verifica la disponibilidad del token */
    public function obtieneToken() {
        if( $this->buscaToken() ) {
                return $this->token;
            } else {
                $this->ids = $this->idty();
                $this->getFiel();
                $this->generaInformacionAutenticacion();
                return $this->autenticacion();
        }
    }

    /*********************************
     *      METODOS PRIVADOS
     *********************************/
    
    /* Genera el proceso de autenticacion con el SAT */
    private function autenticacion() {
        $this->msjAuth();
        $headers = array (
                "Accept: text/xml",
                "Content-Type: text/xml; charset=utf-8",
                "cache-control: no-cache",
                "SOAPAction: http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica"
            );

        try{
            $curl = $this->transmisionCURl( $this->urlSAT , $this->msjAuth , $headers , 'autenticacion' );
            $this->obtieneDatos();
        } catch( Exception $e ) {
            trigger_error( "ErrAuth:".$e->getMessage() );
        }
        
    }

    /* Genera el mensaje de autenticacion */
    private function msjAuth() {
        $this->timeStamp();
        $this->msjAuth  = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                        . 'xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
                        . '<s:Header>'
                        . '<o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">';
        $this->msjAuth .= str_replace( ' xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"' , '' , $this->timeStamp );
        $this->msjAuth .= '<o:BinarySecurityToken u:Id="'.$this->ids[ 0 ].'" '
                            . 'ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" '
                            . 'EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
                            . $this->certificadoB64
                        . '</o:BinarySecurityToken>';
        $this->msjAuth .= '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">';
        $this->msjAuth .= str_replace( ' xmlns="http://www.w3.org/2000/09/xmldsig#"' , '' , $this->signedInfo );
        $this->msjAuth .= '<SignatureValue>' . $this->signature . '</SignatureValue>'
                        . '<KeyInfo>'
                            . '<o:SecurityTokenReference>'
                                . '<o:Reference '
                                . 'ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" '
                                . 'URI="#'.$this->ids[ 0 ].'"/>'
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

    /* Metodo que genera el timeStamp del mensaje */
    private function timeStamp() {
        $this->timeStamp = '<u:Timestamp xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" u:Id="'.$this->ids[ 1 ].'">'
                    . '<u:Created>'.$this->fechaCrea.'</u:Created>'
                    . '<u:Expires>'.$this->fechaExpira.'</u:Expires>'
                    . '</u:Timestamp>';
        $this->digestValue = $this->digestValue( $this->timeStamp );
        $this->signedInfo();
    }

    /* Metodo que regresa el sello a enviar */
    private function signedInfo() {
        $this->signedInfo = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
                          . '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
                          . '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
                          . '<Reference URI="#'.$this->ids[ 1 ].'">'
                          . '<Transforms>'
                          . '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
                          . '</Transforms>'
                          . '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
                          . '<DigestValue>'.$this->digestValue.'</DigestValue>'
                          . '</Reference>'
                          . '</SignedInfo>';
        $this->signature = $this->sello( $this->signedInfo );
    }

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

    /* Inicializacion de datos */
    private function generaInformacionAutenticacion() {
        $this->fechaCrea      = date( 'Y-m-d' ) . 'T' . date( 'H:i:s' , strtotime( '+ ' . $this->diffMinServSat.' minute' ) ) . '.117Z';
        $this->fechaExpira    = date( 'Y-m-d' ) . 'T' . date( 'H:i:s' , strtotime( '+ ' . ( $this->diffMinServSat + 5 ) . ' minute' ) ) . '.117Z';
        $this->certificadoB64 = $this->obtieneCertificado();
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
    private function guardaToken() {return false;
        $this->dbCon->setDabataseClient( $this->database );
        $sql = " INSERT INTO ".$this->database.".cfd_tokenSAT (created, expires, token)"
             . " VALUES ('".$this->created."', '".$this->expires."', '".$this->token."');";
        $this->dbCon->traedatosmysql( $sql );
    }

 }
 