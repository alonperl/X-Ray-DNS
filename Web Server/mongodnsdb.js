var mongoose = require('mongoose');

/*exports.connectToDb = function() {
 return mongoose.connect('mongodb://127.0.0.1/rawdns');
};*/
var Schema = mongoose.Schema;
var rawdnsSchema = new Schema({
	user_agent: String,
	part: String,
	total_hit_count: Number,
	attack_hit_count: Number,
	line: String,
	USE_LINE: Number,
	representor: Number,
	origin_IP: String,
	country: String,
	ISP: String,
	IP_UNUSED: String,
	outbound_IPs: String,
	outbound_ISPs: String,
	outbound_ASNs: String,
	outbound_countries: String,
	time_unix: Number,
	time: String,
	ref_cache_count_max_UNUSED: Number,
	ref_cache_count_maxpop: Number,
	ans_cache_count_max_UNUSED: Number,
	ans_cache_count_maxpop: Number,
	hits: Number,
	batches_seen: Number,
	hit_rate: Number,
	hit2: Number,
	hit2_rate: Number,
	pure_hit_rate: Number,
	blank1: String,
	test_dname_weak: Number,
	v_dname_weak: String,
	test_ns0: Number,
	v_ns0: String,
	test_ns0_auth: Number,
	v_ns0_auth: String,
	test_ns: Number,
	v_ns: String,
	test_ns_auth: Number,
	v_ns_auth: String,
	test_ns2: Number,
	v_ns2: String,
	test_ns2_auth: Number,
	v_ns2_auth: String,
	test_b4: Number,
	v_b4: String,
	test_u1_auth: Number,
	v_u1_auth: String,
	test_u3_2: Number,
	v_u3_2: String,
	test_u3_3: Number,
	v_u3_3: String,
	test_u3_4: Number,
	v_u3_4: String,
	test_w7: Number,
	v_w7: String,
	test_w8: Number,
	v_w8: String,
	test_ns_a_ns: Number,
	v_ns_a_ns: String,
	test_ns_a_a: Number,
	v_ns_a_a: String,
	test_x_ns_a_ns: Number,
	v_x_ns_a_ns: String,
	test_x_ns_a_a: Number,
	v_x_ns_a_a: String,
	test_dname_DELAYED: Number,
	v_dname_DELAYED: String,
	test_ak1_DELAYED: Number,
	v_ak1_DELAYED: String,
	test_w11_DELAYED: Number,
	v_w11_DELAYED: String,
	test_w11bis_DELAYED: Number,
	v_w11bis_DELAYED: String,
	blank2: String,
	nonzero_columns: Number,
	good_columns: Number,
	anomalous_columns: Number,
	num_tests: Number,
	sig_mask: String,
	sig: String,
	matches: String,
	sig_guess: String,
	sig_guess_match: String,
	sig_multimatch: String,
	xor_multimatch: String,
	multimatch_names: String,
	min_Hamming: Number,
	hamming_guess: String,
	FINAL_signame: String,
	version_bind: String,
	min_port: Number,
	max_port: Number,
	port_range: Number,
	port_strategy: String,
	distinctive_ports: Number,
	BIND_QID_algo: String,
	QID_algo_match_count: Number,
	total_even_QIDs: Number,
	QID_match_ratio: String,
	best_port_delta: String,
	amount: Number,
	total_delta_tests: Number
  });

var moncon = mongoose.connect('mongodb://127.0.0.1:27017/rawdnsdb');
var Rawdnsresdb = moncon.model('Rawdnsresdb', rawdnsSchema);
	//moncon.disconnect();

exports.showcontent = function(req,res){
        //var moncon = mongoose.connect('mongodb://127.0.0.1:27017/rawdnsdb');
        //var Rawdnsresdb = moncon.model('Rawdnsresdb');
	Rawdnsresdb.find({},'-_id line',function(err, bla){
        res.send(bla);
	});
};
exports.get_country_users_graph = function(req,res){
	//var moncon = mongoose.connect('mongodb://127.0.0.1:27017/rawdnsdb');
        //var Rawdnsresdb = moncon.model('Rawdnsresdb');

        Rawdnsresdb.find({},'-_id country',function(err, found){
		var found_list = []
                var sw_stat = {}
                for(var i = 0; i < found.length; ++i) {
                        found_list.push(found[i]["country"]);
                }
		 getCounter(found_list, function(arr){
                        res.send(arr);
                });
        });
};
exports.get_isp_graph = function(req,res){
	//var moncon = mongoose.connect('mongodb://127.0.0.1:27017/rawdnsdb');
	//var Rawdnsresdb = moncon.model('Rawdnsresdb');

	Rawdnsresdb.find({},'-_id ISP',function(err, found){
		var found_list = []
		for(var i = 0; i < found.length; ++i){
			if(found[i]["ISP"].length == 0) {
				found_list.push("Unknown");
			}
			else {
				found_list.push(found[i]["ISP"]);
			}
		}
		getCounter(found_list, function(arr){
			res.send(arr);
		});
//                res.send(found_list);
	});
};
exports.is_scan_done = function(req,res){
	 var ip = req.connection.remoteAddress.replace(/^.*:/,'');
	 Rawdnsresdb.findOne({'origin_IP': ip},'-_id origin_IP',function(err, found){
		console.log(found);
		if(found != null) {
console.log("can get statistics");
	res.send("OK");
		}
		else{
			console.log("NO scan from ip " + ip);
			res.send("CANT GET STATISTICS");
		}
	});
}

exports.count_entries = function(req,res){
Rawdnsresdb.count({},function(err, found){
	console.log("entries " + found);
	res.send(" "+found);
});
}

exports.get_sw_graph = function(req,res){
    //    var moncon = mongoose.connect('mongodb://127.0.0.1:27017/rawdnsdb');
      //  var Rawdnsresdb = moncon.model('Rawdnsresdb');

        Rawdnsresdb.find({},'-_id FINAL_signame',function(err, found){
		var found_list = []
		var sw_stat = {}
		for(var i = 0; i < found.length; ++i) {
			if(found[i]["FINAL_signame"].length == 0) {
				found_list.push("Unknown");
			}
			else {
				found_list.push(found[i]["FINAL_signame"]);
			}
		}
		for(var i = 0; i < found_list.length; ++i) {
			if(found_list[i].includes("|")) {
				var final_ = found_list[i].split("|");
				//console.log(final_);
				for(var k = 0; k< final_.length; ++k) {
					 if(final_[k].includes("+")) {
                                                var comb_ = final_[k].split("+");
											                                                for(var j=0; j< comb_.length; ++j){
				
					removeIntChars(comb_[j],function(stipped){
							stip = stipped;
							 if(!sw_stat[stip]){ sw_stat[stip] = 0;}
							 sw_stat[stip] = sw_stat[stip] + 0.5*(1/final_.length);
							});													 }
                                        }
					else {
				//		 console.log("no +  " + final_[k]);

						removeIntChars(final_[k],function(stipped) {
							stip = stipped;
						        if(!sw_stat[stip]){ sw_stat[stip] = 0;}
					        	 sw_stat[stip] = sw_stat[stip] + (1/final_.length);
						});	
											
					}
				}
			}
			else {
				//console.log("no | :  " + found_list[i]);
				if(found_list[i].includes("+")) {
                                                var comb_ = found_list[i].split("+");
                                                                                                                                     for(var j=0; j< comb_.length; ++j){
//                                console.log("no | single : " + comb_[j]);
                                        removeIntChars(comb_[j],function(stipped){
                                                        stip = stipped;
                                                         if(!sw_stat[stip]){ sw_stat[stip] = 0;}
                                                         sw_stat[stip] = sw_stat[stip] + 0.5;
                                                        });                                                                                                      }
                                        }
				else{


					removeIntChars(found_list[i],function(stipped) {
						stip = stipped;
						 if(!sw_stat[stip]){
	                                        	sw_stat[stip] = 0;}
						++sw_stat[stip];
					});
				}
			
			 	
			}
		}
//		console.log(sw_stat);	
	

		res.send(sw_stat);
	});

//        res.send(bla);
	//console.log(bla);
	//moncon.disconnect();

       
};

// create trim operation for String
if(typeof(String.prototype.trim) === "undefined")
{
    String.prototype.trim = function() 
    {
        return String(this).replace(/^\s+|\s+$/g, '');
    };
}

function removeIntChars(str,func) {
//	console.log(str);
	func(str.replace("!","").replace("*","").replace("(","").replace(")","").trim());
}
function getCounter(arr, func) {
	result = { };
	for(var i = 0; i < arr.length; ++i) {
	    if(!result[arr[i]])
        	result[arr[i]] = 0;
	    ++result[arr[i]];
	}	
	func(result);
}

exports.get_os_graph = function(req,res){
//        var moncon = mongoose.connect('mongodb://127.0.0.1:27017/rawdnsdb');
  //      var Rawdnsresdb = moncon.model('Rawdnsresdb');

        Rawdnsresdb.find({},'-_id port_strategy',function(err, found){
                var found_list = []
                for(var i = 0; i < found.length; ++i) {

                        found_list.push(found[i]["port_strategy"].split(" ")[0]);
                }

				getCounter(found_list, function(arr){
					res.send(arr);
				});
        });


};

exports.get_ports_graph = function(req,res){
//        var moncon = mongoose.connect('mongodb://127.0.0.1:27017/rawdnsdb');
	//      var Rawdnsresdb = moncon.model('Rawdnsresdb');

	Rawdnsresdb.find({},'-_id distinctive_ports amount total_delta_tests',function(err, found){
		var found_list = []
		for(var i = 0; i < found.length; ++i) {
		if(found[i]["amount"]>0){
			if (found[i]["total_delta_tests"]>20)
			{
				if (((found[i]["amount"]/found[i]["total_delta_tests"])>0.5) || (found[i]["distinctive_ports"]<10))
				{
					found_list.push("UDP_port_predictable");
				}
			}
			else if(found[i]["distinctive_ports"]<10) {
					found_list.push("UDP_port_predictable");
			}
			else
			{
				found_list.push("UDP_port_unpredictable");
			}
		}
		}


		getCounter(found_list, function(arr){
			res.send(arr);
		});
	});
};

exports.get_txids_graph = function(req,res){

	Rawdnsresdb.find({},'-_id QID_algo_match_count QID_match_ratio',function(err, found){
		var found_list = []
		for(var i = 0; i < found.length; ++i) {
			if ((found[i]["QID_algo_match_count"]>2) && (found[i]["QID_match_ratio"]>0.5))
			{
				found_list.push("TXIDs_predictable");
			}
			else
			{
				found_list.push("TXIDs_unpredictable");
			}
		}

		getCounter(found_list, function(arr){
			res.send(arr);
		});
	});
};

exports.get_cache_graph = function(req,res){
//        var moncon = mongoose.connect('mongodb://127.0.0.1:27017/rawdnsdb');
	//      var Rawdnsresdb = moncon.model('Rawdnsresdb');

	Rawdnsresdb.find({},'-_id ref_cache_count_maxpop',function(err, found){
		var found_list = []
		for(var i = 0; i < found.length; ++i) {
			if(found[i]["ref_cache_count_maxpop"] >=10){
				found_list.push("10+");
			}else{
			found_list.push(found[i]["ref_cache_count_maxpop"]);
			}
		}
		getCounter(found_list, function(arr){
			res.send(arr);
		});
	});
}


exports.addnewresults = function(results,res) {
	console.log("got new results to add from :" +results[3]);
	mongoose.Promise = global.Promise;
//create the resultsJson

var resultsJson = {
user_agent: results[100],
part: results[0],
total_hit_count: parseInt(results[1]),
attack_hit_count: parseInt(results[2]),
line:results[3],
USE_LINE: parseInt(results[4]),
representor: parseInt(results[5]),
origin_IP: results[6],
country: results[7],
ISP: results[8],
IP_UNUSED: results[9],
outbound_IPs: results[10],
outbound_ISPs: results[11],
outbound_ASNs: results[12],
outbound_countries: results[13],
time_unix: parseFloat(results[14]),
time: results[15],
ref_cache_count_max_UNUSED: parseInt(results[16]),
ref_cache_count_maxpop: parseInt(results[17]),
ans_cache_count_max_UNUSED: parseInt(results[18]),
ans_cache_count_maxpop: parseInt(results[19]),
hits: parseInt(results[20]),
batches_seen: parseInt(results[21]),
hit_rate: parseFloat(results[22]),
hit2: parseInt(results[23]),
hit2_rate: parseFloat(results[24]),
pure_hit_rate: parseFloat(results[25]),
blank1: results[26],
test_dname_weak: ((results[27]) ? parseFloat(results[27].split("(")[1].split(")")[0]): -1),
v_dname_weak: results[28],
test_ns0: ((results[29]) ? parseFloat(results[29].split("(")[1].split(")")[0]): -1),
v_ns0: results[30],
test_ns0_auth: ((results[31]) ? parseFloat(results[31].split("(")[1].split(")")[0]): -1),
v_ns0_auth: results[32],
test_ns: ((results[33]) ? parseFloat(results[33].split("(")[1].split(")")[0]): -1),
v_ns: results[34],
test_ns_auth: ((results[35]) ? parseFloat(results[35].split("(")[1].split(")")[0]): -1),
v_ns_auth: results[36],
test_ns2: ((results[37]) ? parseFloat(results[37].split("(")[1].split(")")[0]): -1),
v_ns2: results[38],
test_ns2_auth: ((results[39]) ? parseFloat(results[39].split("(")[1].split(")")[0]): -1),
v_ns2_auth: results[40],
test_b4: ((results[41]) ? parseFloat(results[41].split("(")[1].split(")")[0]): -1),
v_b4: results[42],
test_u1_auth: ((results[43]) ? parseFloat(results[43].split("(")[1].split(")")[0]): -1),
v_u1_auth: results[44],
test_u3_2: ((results[45]) ? parseFloat(results[45].split("(")[1].split(")")[0]): -1),
v_u3_2: results[46],
test_u3_3: ((results[47]) ? parseFloat(results[47].split("(")[1].split(")")[0]): -1),
v_u3_3: results[48],
test_u3_4: ((results[49]) ? parseFloat(results[49].split("(")[1].split(")")[0]): -1),
v_u3_4: results[50],
test_w7: ((results[51]) ? parseFloat(results[51].split("(")[1].split(")")[0]): -1),
v_w7: results[52],
test_w8: ((results[53]) ? parseFloat(results[53].split("(")[1].split(")")[0]): -1),
v_w8: results[54],
test_ns_a_ns: ((results[55]) ? parseFloat(results[55].split("(")[1].split(")")[0]): -1),
v_ns_a_ns: results[56],
test_ns_a_a: ((results[57]) ? parseFloat(results[57].split("(")[1].split(")")[0]): -1),
v_ns_a_a: results[58],
test_x_ns_a_ns: ((results[59]) ? parseFloat(results[59].split("(")[1].split(")")[0]): -1),
v_x_ns_a_ns: results[60],
test_x_ns_a_a: ((results[61]) ? parseFloat(results[61].split("(")[1].split(")")[0]): -1),
v_x_ns_a_a: results[62],
test_dname_DELAYED: ((results[63]) ? parseFloat(results[63].split("(")[1].split(")")[0]): -1),
v_dname_DELAYED: results[64],
test_ak1_DELAYED: ((results[65]) ? parseFloat(results[65].split("(")[1].split(")")[0]): -1),
v_ak1_DELAYED: results[66],
test_w11_DELAYED: ((results[67]) ? parseFloat(results[67].split("(")[1].split(")")[0]): -1),
v_w11_DELAYED: results[68],
test_w11bis_DELAYED: ((results[69]) ? parseFloat(results[69].split("(")[1].split(")")[0]): -1),
v_w11bis_DELAYED: results[70],
blank2: results[71],
nonzero_columns: parseInt(results[72]),
good_columns: parseInt(results[73]),
anomalous_columns: parseInt(results[74]),
num_tests: parseInt(results[75]),
sig_mask: results[76],
sig: results[77],
matches: results[78],
sig_guess: results[79],
sig_guess_match: results[80],
sig_multimatch: results[81],
xor_multimatch: results[82],
multimatch_names: results[83],
min_Hamming: parseInt(results[84]),
hamming_guess: results[85],
FINAL_signame: results[86],
version_bind: results[87],
min_port: parseInt(results[88]),
max_port: parseInt(results[89]),
port_range: parseInt(results[90]),
port_strategy: results[91],
distinctive_ports: parseInt(results[92]),
BIND_QID_algo: results[93],
QID_algo_match_count: parseInt(results[94]),
total_even_QIDs: parseInt(results[95]),
QID_match_ratio: parseInt(results[96]),
best_port_delta: results[97],
amount: parseInt(results[98]),
total_delta_tests: parseInt(results[99])
};
//console.log(resultsJson);
var data = new Rawdnsresdb(resultsJson);
console.log("saving results to Rawdnsresdb : "+results[3]);
data.save(function(err, data){
	if(err){console.log(err);}
	else{
		Rawdnsresdb.count(function(err, c){
			console.log('db count : '+ c);
		});
		//console.log(data);
	}
});
console.log("results #"+results[3]+" saved to Rawdnsresdb");
res.json(resultsJson);
    
};
/*
exports.addnewresults = function(jsonobj, res) {
 let conn = mongoose.connectToDb();
    let rawdns = conn.model('rawdns');
    rawdns.findOne({ line: jsonobj.line }, function (err, fline) {
            if (err) {
                res.send({success: false, error: err});
                conn.disconnect();
            }
            else if (fline) {
                res.send({success:false, error: "line " + jsonobj.line + " already exists."});
                conn.disconnect();
            }
            else {
                let tempRes = new rawdns(jsonobj);
                tempRes.save(function (err, tempRes) {
                    if (err) {
                        res.send({success:false, error: err});
                    }
                    else {res.send(jsonobj);}
                    conn.disconnect();
                });
            }
        });
    }
    else {
        res.send({success: false, error: " undefined"});
        conn.disconnect();
    }
};*/
