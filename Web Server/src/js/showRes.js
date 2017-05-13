function showRes() {
    var xmlhttp = new XMLHttpRequest();
    xmlhttp.onreadystatechange = function () {
        if (this.readyState == 4 && this.status == 200) {
            var jsonRes = JSON.parse(xmlhttp.responseText);
            $(".evaluation").hide();
            document.getElementById("showResultsBtn").style.display = "none";
            document.getElementById("resultsTable").style.visibility = "visible";

            document.getElementById("origin_IP").innerHTML = jsonRes["origin_IP"];
            document.getElementById("outbound_countries").innerHTML = jsonRes["outbound_countries"].split("#")[0];
            document.getElementById("ISP").innerHTML = jsonRes["ISP"];

            var outIPsSplt = jsonRes["outbound_IPs"].split("|");
            if (outIPsSplt) {
                for (var i = 0; i < outIPsSplt.length; i++) {
                    outIPsSplt[i] = outIPsSplt[i].split("#")[0];
                }
            }
            document.getElementById("outbound_IPs").innerHTML = outIPsSplt;


            var outISPsSplt = jsonRes["outbound_ISPs"].split("|");
            if (outISPsSplt) {
                for (var i = 0; i < outISPsSplt.length; i++) {
                    outISPsSplt[i] = outISPsSplt[i].split("#")[0];
                }
            }

            document.getElementById("outbound_ISPs").innerHTML = outISPsSplt;

            var checkIfMinus = ""
            if (jsonRes["test_dname_weak"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_dname_weak"] * 100;
            }
//            document.getElementById("testNum").innerHTML = 1;
            document.getElementById("percOfSuccess1").innerHTML = checkIfMinus;
			         
            checkIfMinus = ""
            if (jsonRes["test_ns0"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_ns0"] * 100;
            }
//            document.getElementById("testNum").innerHTML = "<br>" + 2;
            document.getElementById("percOfSuccess2").innerHTML = checkIfMinus;

            checkIfMinus = ""
            if (jsonRes["test_ns0_auth"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_ns0_auth"] * 100;
            }
	    document.getElementById("percOfSuccess3").innerHTML = checkIfMinus;

            checkIfMinus = ""
            if (jsonRes["test_ns"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_ns"] * 100;
            }
             document.getElementById("percOfSuccess4").innerHTML = checkIfMinus;
            checkIfMinus = ""
            if (jsonRes["test_ns_auth"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_ns_auth"] * 100;
            }
	     document.getElementById("percOfSuccess5").innerHTML = checkIfMinus;

            checkIfMinus = ""
            if (jsonRes["test_ns2"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_ns2"] * 100;
            }
	     document.getElementById("percOfSuccess6").innerHTML = checkIfMinus;

            checkIfMinus = ""
            if (jsonRes["test_ns2_auth"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_ns2_auth"] * 100;
            }
	 document.getElementById("percOfSuccess7").innerHTML = checkIfMinus;

            checkIfMinus = ""
            if (jsonRes["test_b4"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_b4"] * 100;
            }
	 document.getElementById("percOfSuccess8").innerHTML = checkIfMinus;
            checkIfMinus = ""
            if (jsonRes["test_u1_auth"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_u1_auth"] * 100;
            }
	 document.getElementById("percOfSuccess9").innerHTML = checkIfMinus;

            checkIfMinus = ""
            if (jsonRes["test_u3_2"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_u3_2"] * 100;
            }
	 document.getElementById("percOfSuccess10").innerHTML = checkIfMinus;
            checkIfMinus = ""
            if (jsonRes["test_u3_3"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_u3_3"] * 100;
            }
	 document.getElementById("percOfSuccess11").innerHTML = checkIfMinus;

            checkIfMinus = ""
            if (jsonRes["test_u3_4"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_u3_4"] * 100;
            }
	 document.getElementById("percOfSuccess12").innerHTML = checkIfMinus;

            checkIfMinus = ""
            if (jsonRes["test_w7"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_w7"] * 100;
            }
	 document.getElementById("percOfSuccess13").innerHTML = checkIfMinus;
            checkIfMinus = ""
            if (jsonRes["test_w8"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_w8"] * 100;
            }
	 document.getElementById("percOfSuccess14").innerHTML = checkIfMinus;
/*
            checkIfMinus = ""
            if (jsonRes["test_ns_a_ns"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_ns_a_ns"] * 100;
            }

            checkIfMinus = ""
            if (jsonRes["test_ns_a_a"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_ns_a_a"] * 100;
            }

            checkIfMinus = ""
            if (jsonRes["test_x_ns_a_ns"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_x_ns_a_ns"] * 100;
            }

            checkIfMinus = ""
            if (jsonRes["test_x_ns_a_a"] === -1) {
                checkIfMinus = "undefind"
            }
            else {
                checkIfMinus = jsonRes["test_x_ns_a_a"] * 100;
            }
*/
        }

    };
    var url = "finalresults?line=" + token;
    xmlhttp.open("GET", url, true);
    xmlhttp.send();
}
