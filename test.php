<?php
ini_set("display_errors","0");
/*
 * Script que prueba las opreciones de descarga masiva
 */

 /* Autenticacion 
include_once './Auth.php';
$auth = new Auth();
$auth->obtieneToken();

echo $auth->token;*/


/* Solicitud 
$datos = array(
    'rfcEmisor' => 'API6609273E0', 'rfcReceptor' => 'RESC840317J72' , 'rfcSolicitante' => 'RESC840317J72', 
    'fechaInicial' => '2018-10-01T00:00:00', 'fechaFinal' => '2018-10-31T23:59:59', 'tipoSolicitud' => 'CFDI'
);
include_once './Solicitud.php';
$solicitud = new Solicitud();
$solicitud->generaPeticionDescarga( $datos );

echo $solicitud->response;*/

/* Verificacion */
$datos = array(
    'idSolicitud' => '50dc7dcb-ff93-4e39-9f74-cbb5721aea0c' , 'rfcSolicitante' => 'RESC840317J72' 
);
include_once './Verificacion.php';
$verifica = new Verificacion();
$verifica->verificaDescarga( $datos );

echo $verifica->response;
echo "\n";
echo serialize( $verifica->paquetes );

/* Descarga 
$datos = array(
    'idPaquete' => '' , 'rfcSolicitante' => 'RESC840317J72' 
);
include_once './Descarga.php';
$descarga = new Descarga();
$descarga->generaDescarga( $datos );

echo $descarga->response;*/
