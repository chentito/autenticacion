<?php
/*
 * Clase que realiza la solicitud de descarga ante el SAT
 *
 * @Autor Mexagon.net / Carlos Reyes
 * @Fecha Diciembre 2018
 */
 require_once './Auth.php';

 class Descarga extends Utils {
    /*
     * Atributos publicos
     */
    public $error = '';
    public $idSolicitud = '';
    public $codigo = '';
    public $mensaje = '';
    public $paquete = '';

    /*
     * Atributos privados
     */
    private $urlSAT = 'https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc';
    private $ids = array();
    private $arrData = array();
    private $msjDes = '';
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

    /* metodo que ejecuta la peticion de descarga */
    public function generaDescarga( $datos ) {
        $this->arrData = $datos;
        $this->token = $this->creaToken();  
        $this->ids = $this->idty();
        $this->getFiel(); 
        $this->ejecutaDescarga();
    }

    /*********************************
     *      METODOS PRIVADOS
     *********************************/
    /* Genera el llamado al proceso de verificacion de descarga */
    private function ejecutaDescarga() {
        $this->msjDes();
        $headers = array (
            'Accept-Encodign: gzip,deflate',
            'Content-Type: text/xml; charset=UTF-8',            
            'Authorization: WRAP access_token="'.$this->token.'"',
            'SOAPAction: http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar',
            'Content-Length: '.strlen( $this->msjDes )
        );

        try{
            $curl = $this->transmisionCURl( $this->urlSAT , $this->msjDes , $headers , 'descarga' );
            $this->obtieneDatos();
        } catch( Exception $e ) {
            trigger_error( $e->getMessage() );
        }
    }

    /* Metodo que genera el mensaje a enviar al sat */
    private function msjDes() {
        $this->timeStamp();
        $this->msjDes = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
                          . 'xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx" '
                          . 'xmlns:xd="http://www.w3.org/2000/09/xmldsig#">'
                          . '<soapenv:Header/>'
                          . '<soapenv:Body>'
                          . '<des:PeticionDescargaMasivaTercerosEntrada>'
                            . '<des:peticionDescarga IdPaquete="'.$this->arrData[ 'idPaquete' ].'" '
                                . 'RfcSolicitante="'.$this->arrData[ 'rfcSolicitante' ].'">'
                                . '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">';
        $this->msjDes .= str_replace( ' xmlns="http://www.w3.org/2000/09/xmldsig#"' , '' , $this->signedInfo );
        $this->msjDes .= '<SignatureValue>'.$this->signature.'</SignatureValue>'
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
                            . '</des:peticionDescarga>'
                          . '</des:PeticionDescargaMasivaTercerosEntrada>'
                          . '</des:VerificaSolicitudDescarga>'
                          . '</soapenv:Body>'
                          . '</soapenv:Envelope>';
    }

    /* Metodo que genera el digest value */
    private function timeStamp() {
        $this->timeStamp = '<des:PeticionDescargaMasivaTercerosEntrada xmlns:des="http://DescargaMasivaTerceros.sat.gob.mx">'
                         . '<des:peticionDescarga IdPaquete="'.$this->arrData[ 'idPaquete' ].'" '
                         . 'RfcSolicitante="'.$this->arrData[ 'rfcSolicitante' ].'"></des:peticionDescarga>'
                         . '</des:PeticionDescargaMasivaTercerosEntrada>';
        $this->digestValue = $this->digestValue( $this->timeStamp );
        $this->signedInfo();
    }

    /* Metodo que regresa el sello a enviar */
    private function signedInfo() {
        $this->signedInfo = '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">'
                          . '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
                          . '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
                          . '<Reference URI="">'
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
            } elseif( $dom->getElementsByTagName( 'RespuestaDescargaMasivaTercerosSalida' )->length > 0 ) {
                $this->paquete = utf8_decode( $dom->getElementsByTagName( 'Paquete' )->item( 0 )->nodeValue );
                
        }
    }

 }
