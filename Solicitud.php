<?php
/*
 * Clase que realiza la solicitud de descarga ante el SAT
 *
 * @Autor Mexagon.net / Carlos Reyes
 * @Fecha Diciembre 2018
 */
 require_once './Auth.php';

 class Solicitud extends Utils {
    /*
     * Atributos publicos
     */
    public $error = '';
    public $idSolicitud = '';
    public $codigo = '';
    public $mensaje = '';

    /* 
     * Atributos privados
     */
    private $urlSATSol = 'https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc';
    private $ids = array();
    private $arrData = array();
    private $msjSol = array();
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

    /* Metodo que realiza la solicitud de descarga */
    public function generaPeticionDescarga( $datos ) {
        $this->arrData = $datos;
        $this->token = $this->creaToken();
        $this->ids = $this->idty();
        $this->getFiel(); 
        $this->solicitudDescarga();
    }

    /*********************************
     *      METODOS PRIVADOS
     *********************************/

    /* Metodo que realiza la solicitud al sat */
    private function solicitudDescarga() {
        $this->msjSol();
        $headers = array (
            "Content-type: text/xml;charset=\"utf-8\"",
            "Accept: text/xml",
            "Cache-Control: no-cache",
            "Authorization: WRAP access_token=\"".$this->token."\"",
            "SOAPAction: http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga",
            "Content-length: ".strlen( $this->msjSol )
        );

        try{
            $curl = $this->transmisionCURl( $this->urlSATSol , $this->msjSol , $headers , 'solicitud' );
            $this->obtieneDatos();
        } catch( Exception $e ) {
            trigger_error( "ErrSol:".$e->getMessage() );
        }
    }

    /* Genera el mensaje de autenticacion */
    private function msjSol() {
        $this->timeStamp();
        $this->msjSol = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
                          . 'xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" '
                          . 'xmlns:xd="http://www.w3.org/2000/09/xmldsig#">'
                          . '<soapenv:Header/>'
                          . '<soapenv:Body>'
                          . '<des:SolicitaDescarga>'
                            . '<des:solicitud RfcEmisor="'.$this->arrData[ 'rfcEmisor' ].'" RfcReceptor="'.$this->arrData[ 'rfcReceptor' ].'" '
                                . 'RfcSolicitante="'.$this->arrData[ 'rfcSolicitante' ].'" FechaInicial="'.$this->arrData[ 'fechaInicial' ].'" '
                                . 'FechaFinal="'.$this->arrData[ 'fechaFinal' ].'" TipoSolicitud="'.$this->arrData[ 'tipoSolicitud' ].'">'
                                . '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">';
        $this->msjSol .= str_replace( ' xmlns="http://www.w3.org/2000/09/xmldsig#"' , '' , $this->timeStamp );
        $this->msjSol .= '<SignatureValue>'.$this->signature.'</SignatureValue>'
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
                          . '</des:SolicitaDescarga>'
                          . '</soapenv:Body>'
                          . '</soapenv:Envelope>';
    }

    /* Metodo que genera el digest value */
    private function timeStamp() {
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
        $t->obtieneToken();
        return $t->token;
    }

    /* Metodo que obtiene token del responde */
    private function obtieneDatos() {
        $dom = new DOMDocument();
        $dom->loadXML( $this->response );

        if( $dom->getElementsByTagName( 'faultcode' )->length > 0 ) {
                $this->faultstring = utf8_decode( $dom->getElementsByTagName( 'faultstring' )->item( 0 )->nodeValue );
                $this->faultcode   = utf8_decode( $dom->getElementsByTagName( 'faultcode' )->item( 0 )->nodeValue );
            } elseif( $dom->getElementsByTagName( 'SolicitaDescargaResult' )->length > 0 ) {
                $sol = $dom->getElementsByTagName( 'SolicitaDescargaResult' )->item( 0 );
                $this->idSolicitud = utf8_decode( $sol->getAttribute( 'IdSolicitud' ) );
                $this->codigo      = utf8_decode( $sol->getAttribute( 'CodEstatus' ) );
                $this->mensaje     = utf8_decode( $sol->getAttribute( 'Mensaje' ) );
        }
    }

 }
