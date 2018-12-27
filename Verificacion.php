<?php
/*
 * Clase que realiza la verificacion de descarga ante el SAT
 *
 * @Autor Mexagon.net / Carlos Reyes
 * @Fecha Diciembre 2018
 */
require_once './Auth.php';

class verificacion extends Utils {
    /*
     * Atributos publicos
     */
    public $error = '';
    public $idSolicitud = '';
    public $codigo = '';
    public $mensaje = '';
    public $codigoEstatus = '';
    public $estadoSolicitud = '';
    public $codigoEstadoSolicitud = '';

    /*
     * Atributos privados
     */
    private $urlSAT = 'https://srvsolicituddescargamaster.cloudapp.net/VerificaSolicitudDescargaService.svc';
    private $ids = array();
    private $arrData = array();
    private $msjVer = '';
    private $timeStamp = '';
    private $token = '';
    private $certificado = '';
    private $serialNum = '';
    private $issuerName = '';

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

    /* Realiza la verificacion de la descarga */
    public function verificaDescarga( $datos ) {
        $this->arrData = $datos;
        $this->token = $this->creaToken();  
        $this->ids = $this->idty();
        $this->getFiel(); 
        $this->consultaDescarga();
    }

    /*********************************
     *      METODOS PRIVADOS
     *********************************/

    /* Genera el llamado al proceso de verificacion de descarga */
    private function consultaDescarga() {
        $this->msjVer();
        $headers = array (
            'Accept-Encodign: gzip,deflate',
            'Content-Type: text/xml; charset=UTF-8',
            'SOAPAction: http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga',
            'Authorization: WRAP access_token="'.$this->token.'"',
            'Content-Length: 4736',
            'Host: srvsolicituddescargamaster.cloudapp.net'
        );

        try{
            $curl = $this->transmisionCURl( $this->urlSAT , $this->msjVer , $headers , 'verifica' );
            $this->obtieneDatos();
        } catch( Exception $e ) {
            trigger_error( $e->getMessage() );
        }
    }

    /* Genera el mensaje de verificacion */
    private function msjVer() {
        $this->timeStamp();
        $this->msjVer = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
                          . 'xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" '
                          . 'xmlns:xd="http://www.w3.org/2000/09/xmldsig#">'
                          . '<soapenv:Header/>'
                          . '<soapenv:Body>'
                          . '<des:VerificaSolicitudDescarga>'
                            . '<des:solicitud IdSolicitud="'.$this->arrData[ 'idSolicitud' ].'" '
                                . 'RfcSolicitante="'.$this->arrData[ 'rfcSolicitante' ].'">'
                                . '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">';
        $this->msjVer .= str_replace( ' xmlns="http://www.w3.org/2000/09/xmldsig#"' , '' , $this->signedInfo );
        $this->msjVer .= '<SignatureValue>'.$this->signature.'</SignatureValue>'
                                    . '<KeyInfo>'
                                        . '<X509Data>'
                                            . '<X509IssuerSerial>'
                                                . '<X509IssuerName>'.$this->issuerName.'</X509IssuerName>'
                                                . '<X509SerialNumber>'.$this->serialNum.'</X509SerialNumber>'
                                            . '</X509IssuerSerial>'
                                            . '<X509Certificate>'.$this->certificado.'</X509Certificate>'
                                        . '</X509Data>'
                                    . '</KeyInfo>'
                                . '</Signature>'
                            . '</des:solicitud>'
                          . '</des:VerificaSolicitudDescarga>'
                          . '</soapenv:Body>'
                          . '</soapenv:Envelope>';
    }

    /* Metodo que genera el digest value */
    private function timeStamp() {
        $this->timeStamp = '<des:VerificaSolicitudDescarga xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">'
                         . '<des:solicitud IdSolicitud="'.$this->arrData[ 'idSolicitud' ].'" '
                         . 'RfcSolicitante="'.$this->arrData[ 'rfcSolicitante' ].'"></des:solicitud>'
                         . '</des:VerificaSolicitudDescarga>';
        $this->timeStamp = '<des:SolicitaDescarga xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">'
                         . '<des:solicitud FechaFinal="'.$this->arrData[ 'fechaFinal' ].'" FechaInicial="'.$this->arrData[ 'fechaInicial' ].'" '
                         . 'RfcEmisor="'.$this->arrData[ 'rfcEmisor' ].'" RfcReceptor="'.$this->arrData[ 'rfcReceptor' ].'" '
                         . 'RfcSolicitante="'.$this->arrData[ 'rfcSolicitante' ].'" TipoSolicitud="CFDI"></des:solicitud></des:SolicitaDescarga>';
        $this->digestValue = $this->digestValue( $this->timeStamp );
        $this->signedInfo();
    }

    /* Metodo que regresa el sello a enviar */
    private function signedInfo() {
        $this->signedInfo = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
                          . '<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
                          . '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
                          . '<Reference URI="">'
                          . '<Transforms>'
                          . '<Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
                          . '</Transforms>'
                          . '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>'
                          . '<DigestValue>'.$this->digestValue.'</DigestValue>'
                          . '</Reference>'
                          . '</SignedInfo>';
        $this->signature = $this->sello( $this->signedInfo );
        $this->creaDatosSolicitud();
    }

    /* Metodo que extrae los datos necesarios del certificado */
    private function creaDatosSolicitud() {
        $cer = $this->archivoCer;
        $this->certificado = base64_encode( file_get_contents( $cer ) );
        exec( '/usr/bin/openssl x509 -inform DER -outform PEM -in  ' . $cer . ' -pubkey > ' . $cer . '.pem ' );
        $datos = openssl_x509_parse( file_get_contents( $cer . '.pem' ) );
        $this->serialNum   = $datos[ 'serialNumber' ];
        foreach ( $datos[ 'issuer' ] as $key => $value) {
            $this->issuerName .= $key.'='.$value.',';
        }
        $this->issuerName  = substr( $this->issuerName , 0 , -1 );
        $this->temps[]     = $cer . '.pem ';
    }

    /* Metodo que obtiene el token para la autenticacion */
    private function creaToken() {
        $t = new Auth();
        return $t->obtieneToken();
    }

    /* Metodo que obtiene token del responde */
    private function obtieneDatos() {
        $dom = new DOMDocument();
        $dom->loadXML( $this->response );

        if( $dom->getElementsByTagName( 'faultcode' )->length > 0 ) {
                $this->faultstring = utf8_decode( $dom->getElementsByTagName( 'faultstring' )->item( 0 )->nodeValue );
                $this->faultcode   = utf8_decode( $dom->getElementsByTagName( 'faultcode' )->item( 0 )->nodeValue );
            } elseif( $sol = $dom->getElementsByTagName( 'VerificaSolicitudDescargaResult' )->length > 0 ) {
                $this->codigoEstatus         = utf8_decode( $sol->getAttribute( 'CodEstatus' ) );
                $this->estadoSolicitud       = utf8_decode( $sol->getAttribute( 'EstadoSolicitud' ) );
                $this->codigoEstadoSolicitud = utf8_decode( $sol->getAttribute( 'CodigoEstadoSolicitud' ) );
                $this->mensaje               = utf8_decode( $sol->getAttribute( 'Mensaje' ) );
        }
    }

}
