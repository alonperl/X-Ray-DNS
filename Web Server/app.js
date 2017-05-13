
var _dir = '/etc/webserver/'
var currentdate = new Date(); 
var datetime = currentdate.getDate() + "_"
                + (currentdate.getMonth()+1)  + "_" 
                + currentdate.getFullYear() + "_"  
                + currentdate.getHours() + "_"  
                + currentdate.getMinutes();


var express = require('express');
var http = require('http');
var app = express();
var mongoose = require('mongoose');
var exec = require('child_process').exec;
var request = require("request");
var current_index;
var fs = require('fs');
var fs = require('fs');
var util = require('util');
var log_file = fs.createWriteStream(_dir + 'logs/debug_'+datetime+'.log', {flags : 'w'});
var log_stdout = process.stdout;
console.log = function(d) { //
  var date = new Date().toLocaleString();
  log_file.write(date + "#" + util.format(d) + '\n');
  log_stdout.write(date + "#" + util.format(d) + '\n');
};
var _error = console.error;
console.error = function(errMessage){
      var date = new Date().toLocaleString();
      log_file.write(date + "#" + util.format(errMessage) + '\n');
     _error.apply(console,arguments);
  };

var url = require('url');
var syncexec = require('sync-exec');
var parse = require('csv').parse;
var dnsdb = require('/etc/webserver/mongodnsdb.js');

fs.readFile('/etc/webserver/data/counter', 'utf8', function (err,data) {
  if (err) {
    return console.log(err);
  }
  current_index = parseInt(data, 10);
});

app.use(express.static('/etc/webserver/src'))
app.get('/', function (req, res) {
  res.send("Please enter http://wprod.sit.fraunhofer.de/main.html");
})
app.use('/showcontent', dnsdb.showcontent);
app.use('/is_scan_done', dnsdb.is_scan_done);
app.use('/get_sw_graph', dnsdb.get_sw_graph);
app.use('/get_os_graph', dnsdb.get_os_graph);
app.use('/get_isp_graph', dnsdb.get_isp_graph);
app.use('/count_entries', dnsdb.count_entries);
app.use('/get_ports_graph', dnsdb.get_ports_graph);
app.use('/get_txids_graph', dnsdb.get_txids_graph);
app.use('/get_cache_graph', dnsdb.get_cache_graph);
app.use('/get_country_users_graph', dnsdb.get_country_users_graph);
app.get('/lineindex', function (req, res) {
  current_index += 1; 
  fs.truncate("/etc/webserver/data/counter", 0, function() {
    fs.writeFile("/etc/webserver/data/counter", current_index, function(err) {
    	if(err) {
        	return console.log(err);
    	}
	console.log(current_index);
	console.log(req.connection.remoteAddress.replace(/^.*:/,'').replace(/\./g,'-'));
   	console.log("The file was saved!");
    });
  }); 
  res.json({line:current_index,ip:req.connection.remoteAddress.replace(/^.*:/,'').replace(/\./g,'-')});

})
//pprod request
app.get('/finalresults', function(req,res) {
  console.log("finalresults"+req.query.line);
  
  request({
    uri: "http://pprod.sit.fraunhofer.de:3000/rawdns_p_"+req.query.line+".txt",
    method: "GET",
    timeout: 10000,
    followRedirect: true,
    maxRedirects: 10
  }).pipe(fs.createWriteStream("/etc/webserver/data/rawdnsfiles/rawdns_p_"+req.query.line+".txt"));
//aprod request
request({
    uri: "http://aprod.sit.fraunhofer.de:3000/rawdns_a_"+req.query.line+".txt",
    method: "GET",
    timeout: 10000,
    followRedirect: true,
    maxRedirects: 10
  }).pipe(fs.createWriteStream("/etc/webserver/data/rawdnsfiles/rawdns_a_"+req.query.line+".txt"));
//vicprod request
request({
    uri: "http://vicprod.sit.fraunhofer.de:3000/rawdns_v_"+req.query.line+".txt",
    method: "GET",
    timeout: 10000,
    followRedirect: true,
    maxRedirects: 10
  }).pipe(fs.createWriteStream("/etc/webserver/data/rawdnsfiles/rawdns_v_"+req.query.line+".txt"));
//running the perl script
var resArr = {};
var valArr = [];
var rpath = "/etc/webserver/data/rawdnsfiles/rawdns"+req.query.line+".csv";
var runperl = "perl /etc/webserver/data/rawdnsfiles/analyze_rawdns_multimatch2.pl "+"/etc/webserver/data/rawdnsfiles/rawdns_p_"+req.query.line+".txt "+ "/etc/webserver/data/rawdnsfiles/rawdns_v_"+req.query.line+".txt "+ "/etc/webserver/data/rawdnsfiles/rawdns_a_"+req.query.line+".txt "+ "tt25 0 0 0 > /etc/webserver/data/rawdnsfiles/rawdns"+req.query.line+".csv";
seqOfExec(runperl);
function seqOfExec(runperl) {
    exec(runperl, function (error, stdout, stderr) {
        if (error === null) {
            if (stdout) {
                throw Error("Smth goes wrong" + error);
            } else {
		console.log("reading file :" +rpath);
                fs.readFile(rpath, function (err, data) {
					parse(data, function(err, rows) {
						if(rows[1][4] === "1"){
							for(var i = 0; i < rows[0].length; i++){
								resArr[rows[0][i]] = rows[1][i];
								//console.log(rows[1][i]);
								valArr[i] = rows[1][i];
							}
						};
						if(rows[2][4] === "1"){
							for(var i = 0; i < rows[0].length; i++){
								resArr[rows[0][i]] = rows[2][i];
								//console.log(rows[2][i]);
								valArr[i] = rows[2][i];
							}
						};
//						console.log("asdkjjhsadkjsabbdljasndlsandlsakndas");
//						console.log("####################"+req.get('User-Agent'));
//						console.log("asdkjjhsadkjsabbdljasndlsandlsakndas");
						valArr[rows[0].length] = req.get('User-Agent');						
						//var jsonString = JSON.stringify(resArr);
						//console.log(jsonString);
						//send response
						//res.json(resArr);
						//push to DB
						console.log("saving results in db : " +rpath);
						dnsdb.addnewresults(valArr, res);
						
					})
				});

            }
        }
    });
};
});



app.listen(80, function () {
  console.log('Webserver listening on port 80')
})

