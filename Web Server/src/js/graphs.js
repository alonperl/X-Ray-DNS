
      // Load the Visualization API and the corechart package.
      google.charts.load('current', {'packages':['corechart']});


//window.onresize = drawChart;
var xmlhttp_os_graph = new XMLHttpRequest;
	  var xmlhttp_sw_graph = new XMLHttpRequest;
	  var xmlhttp_country_users_graph = new XMLHttpRequest;
	  var xmlhttp_get_isp_graph = new XMLHttpRequest;
	  var xmlhttp_get_cache_graph = new XMLHttpRequest;
	  var xmlhttp_get_ports_graph = new XMLHttpRequest;
	  var xmlhttp_get_txids_graph = new XMLHttpRequest;
	  var xmlhttp_is_scan_done = new XMLHttpRequest;
	var xmlhttp_total_entries =  new XMLHttpRequest;
	  xmlhttp_country_users_graph.onreadystatechange = function() {
                        if (this.readyState == 4 && this.status == 200) {
                        var parsed = JSON.parse(xmlhttp_country_users_graph.responseText);
			//document.getElementsByClassName("graphTitle").style.visibility = "visible";

                          // convert JSON to list of list
                          var arr_res = [["COUNTRY","Measures",{ role : "style"}]];
                      for(var x in parsed){
                                  arr_res.push([x,parsed[x],'color: #339966']);
                           }

                          google.charts.setOnLoadCallback(drawChart);

                          // Callback that creates and populates a data table,
                          // instantiates the pie chart, passes in the data and
                          // draws it.
                          function drawChart() {
                                        var data = google.visualization.arrayToDataTable(arr_res);
				 document.getElementById("usr_graph_title").style.visibility = "visible";
                                  var view = new google.visualization.DataView(data);
                                  view.setColumns([0, 1,
                                                                   { calc: "stringify",
                                                                         sourceColumn: 1,
                                                                         type: "string",
                                                                         role: "annotation" },
                                                                   2]);

                                  var options = {
                                        //title: "Countries users",
					chartArea : { left: '8%', top: '8%', width: "70%", height: "70%" },
					'position': "absolute",
                                        'left': "0%",
                                        'top': "0%",
                                        width: 1200,
                                        height: 500,
					backgroundColor: '#FAFAFA',
                                        bar: {groupWidth: "95%"},
                                        legend: { position: "none" },
                                  };
                                  var chart = new google.visualization.ColumnChart(document.getElementById("usr_graph"));
                                  chart.draw(view, options);

                          }}};
	
	  xmlhttp_get_cache_graph.onreadystatechange = function() {
		  if (this.readyState == 4 && this.status == 200) {
			  var parsed = JSON.parse(xmlhttp_get_cache_graph.responseText);


			  // convert JSON to list of list
			  var arr_res = [["Cache_Count","Detections",{ role : "style"}]];
			  for(var x in parsed){
				  arr_res.push([x,parsed[x],'color: #339966']);
			  }

			  google.charts.setOnLoadCallback(drawChart);

			  // Callback that creates and populates a data table,
			  // instantiates the pie chart, passes in the data and
			  // draws it.
			  function drawChart() {
				  var data = google.visualization.arrayToDataTable(arr_res);
				 document.getElementById("cache_graph_title").style.visibility = "visible";
				  var view = new google.visualization.DataView(data);
				  view.setColumns([0, 1,
					  { calc: "stringify",
						  sourceColumn: 1,
						  type: "string",
						  role: "annotation" },
					  2]);

				  var options = {
					  //title: "Number of Caches",
					chartArea : { left: '8%', top: '8%', width: "70%", height: "70%" },
					  'position': "absolute",
					  'left': "0%",
					  'top': "0%",
					  width: 1200,
					  height: 500,
					   backgroundColor: '#FAFAFA',
					  bar: {groupWidth: "95%"},
					  legend: { position: "none" },
				  };
				  var chart = new google.visualization.ColumnChart(document.getElementById("cache_graph"));
				  chart.draw(view, options);

			  }}};

	  xmlhttp_sw_graph.onreadystatechange = function() {
            		if (this.readyState == 4 && this.status == 200) {
  			var parsed = JSON.parse(xmlhttp_sw_graph.responseText);


			  // convert JSON to list of list
			  var arr_res = [["SW","Detections",{ role : "style"}]];
		      for(var x in parsed){
				  arr_res.push([x,parsed[x],'color: #339966']);
			   }
			  
			  google.charts.setOnLoadCallback(drawChart);

			  // Callback that creates and populates a data table,
			  // instantiates the pie chart, passes in the data and
			  // draws it.
			  function drawChart() {
					var data = google.visualization.arrayToDataTable(arr_res);
				 document.getElementById("sw_graph_title").style.visibility = "visible";

				  var view = new google.visualization.DataView(data);
				  view.setColumns([0, 1,
								   { calc: "stringify",
									 sourceColumn: 1,
									 type: "string",
									 role: "annotation" },
								   2]);

				  var options = {
					//title: "Detected DNS SW",
					chartArea : { left: '8%', top: '8%', width: "70%", height: "70%" },
					position: "absolute",
                                        left: "0%",
                                        top: "0%",
					 backgroundColor: '#FAFAFA',
					width: window.innerWidth*0.8,
					height: 500,
					bar: {groupWidth: "95%"},
					legend: { position: "none" },
				  };
				  var chart = new google.visualization.ColumnChart(document.getElementById("sw_graph"));
				  chart.draw(view, options);
               var url3 = "get_country_users_graph";
                                xmlhttp_country_users_graph.open("GET", url3, true);
                                xmlhttp_country_users_graph.send();

			  
			  }}};
	
	  xmlhttp_os_graph.onreadystatechange = function() {
            		if (this.readyState == 4 && this.status == 200) {
  			var parsed = JSON.parse(xmlhttp_os_graph.responseText);


			  // convert JSON to list of list
			  var arr_res = [];
		      for(var x in parsed){
				  arr_res.push([x,parsed[x]]);
			   }
			  
			  google.charts.setOnLoadCallback(drawChart);

			  // Callback that creates and populates a data table,
			  // instantiates the pie chart, passes in the data and
			  // draws it.
			  function drawChart() {
			document.getElementById("os_graph_title").style.visibility = "visible";	
				// Create the data table.
				var data = new google.visualization.DataTable();
				data.addColumn('string', 'OS');
				data.addColumn('number', 'Count');
				data.addRows(arr_res);

				// Set chart options
				var options = {//'title':'Detected OSes',
						chartArea : { left: '8%', top: '8%', width: "70%", height: "90%" },
							   width:600,
							   position: "absolute",
				                           left: "0%",
                          				   top: "0%",
							 backgroundColor: '#FAFAFA',
							   'height':500};

				// Instantiate and draw our chart, passing in some options.
				var chart = new google.visualization.PieChart(document.getElementById('os_graph'));
				chart.draw(data, options);
			  }
		}};

	  xmlhttp_get_ports_graph.onreadystatechange = function() {
		  if (this.readyState == 4 && this.status == 200) {
			  var parsed = JSON.parse(xmlhttp_get_ports_graph.responseText);


			  // convert JSON to list of list
			  var arr_res = [];
			  for(var x in parsed){
				  arr_res.push([x,parsed[x]]);
			  }

			  google.charts.setOnLoadCallback(drawChart);

			  // Callback that creates and populates a data table,
			  // instantiates the pie chart, passes in the data and
			  // draws it.
			  function drawChart() {
					 document.getElementById("ports_graph_title").style.visibility = "visible";
				  // Create the data table.
				  var data = new google.visualization.DataTable();
				  data.addColumn('string', 'UDP predictable vs non');
				  data.addColumn('number', 'Count');
				  data.addRows(arr_res);

				  // Set chart options
				  var options = {//'title':'UDP ports allocation',
					chartArea : { left: '8%', top: '8%', width: "70%", height: "90%" },
					  width:600,
					  position: "absolute",
					 backgroundColor: '#FAFAFA',
					  left: "0%",
					  top: "0%",
					  'height':500};

				  // Instantiate and draw our chart, passing in some options.
				  var chart = new google.visualization.PieChart(document.getElementById('ports_graph'));
				  chart.draw(data, options);
			  }
		  }};

	  xmlhttp_get_txids_graph.onreadystatechange = function() {
		  if (this.readyState == 4 && this.status == 200) {
			  var parsed = JSON.parse(xmlhttp_get_txids_graph.responseText);


			  // convert JSON to list of list
			  var arr_res = [];
			  for(var x in parsed){
				  arr_res.push([x,parsed[x]]);
			  }

			  google.charts.setOnLoadCallback(drawChart);

			  // Callback that creates and populates a data table,
			  // instantiates the pie chart, passes in the data and
			  // draws it.
			  function drawChart() {
				 document.getElementById("txids_graph_title").style.visibility = "visible";
				  // Create the data table.
				  var data = new google.visualization.DataTable();
				  data.addColumn('string', 'DNS TXIDs');
				  data.addColumn('number', 'Count');
				  data.addRows(arr_res);

				  // Set chart options
				  var options = {//'title':'DNS TXID values allocation',
					chartArea : { left: '8%', top: '8%', width: "70%", height: "90%" },
					  width:600,
					  position: "absolute",
					 backgroundColor: '#FAFAFA',
					  left: "0%",
					  top: "0%",
					  'height':500};

				  // Instantiate and draw our chart, passing in some options.
				  var chart = new google.visualization.PieChart(document.getElementById('txids_graph'));
				  chart.draw(data, options);
			  }
		  }};

	  xmlhttp_get_isp_graph.onreadystatechange = function() {
		  if (this.readyState == 4 && this.status == 200) {
			  var parsed = JSON.parse(xmlhttp_get_isp_graph.responseText);


			  // convert JSON to list of list
			  var data_arr_res = [["ISP","Tested",{ role : "style"}]];
//			var data_arr_res = []
			  for(var x in parsed){
				  data_arr_res.push([x,parsed[x],'color: #339966']);
			  }
				//data_arr_res.sort([{column: 1},{column: 0}]);
//			arr_res.push(data_arr_res);
			  google.charts.setOnLoadCallback(drawChart);

			  // Callback that creates and populates a data table,
			  // instantiates the pie chart, passes in the data and
			  // draws it.
			  function drawChart() {
				  var data = google.visualization.arrayToDataTable(data_arr_res);
				data.sort([{column: 1, desc:true}]);
				 document.getElementById("isp_graph_title").style.visibility = "visible";
				  var view = new google.visualization.DataView(data);
				  view.setColumns([0, 1,
					  { calc: "stringify",
						  sourceColumn: 1,
						  type: "string",
						  role: "annotation" },
					  2]);

				  var options = {
					  //title: "ISP tested",
					chartArea : { left: '40%', top: '1%', width: "70%", height: "99%"},
					  'position': "absolute",
					  'left': "50%",
					  'top': "0%",
					  width: 600,
					  height: data_arr_res.length*35,
					  bar: {groupWidth: "95%"},
					  legend: { position: "none" },
					  backgroundColor: '#FAFAFA'
				  };
				  var chart = new google.visualization.BarChart(document.getElementById("isp_graph"));
				  chart.draw(view, options);

			  }}};
xmlhttp_total_entries.onreadystatechange = function() {
if (this.readyState == 4 && this.status == 200) {
var t = document.createTextNode("DNS X-Ray tool was used"+xmlhttp_total_entries.responseText+" times");
document.getElementById("total_entries").appendChild(t);
};

};
      xmlhttp_is_scan_done.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
              if (xmlhttp_is_scan_done.responseText == "OK") {
                  var url = "get_os_graph";
                  xmlhttp_os_graph.open("GET", url, true);
                  xmlhttp_os_graph.send();
                  var url2 = "get_sw_graph";
                  xmlhttp_sw_graph.open("GET", url2, true);
                  xmlhttp_sw_graph.send();
                  var url3 = "get_country_users_graph";
                  xmlhttp_country_users_graph.open("GET", url3, true);
                  xmlhttp_country_users_graph.send();
                  var url4 = "get_isp_graph";
                  xmlhttp_get_isp_graph.open("GET", url4, true);
                  xmlhttp_get_isp_graph.send();
                  var url5 = "get_cache_graph";
                  xmlhttp_get_cache_graph.open("GET", url5, true);
                  xmlhttp_get_cache_graph.send();
                  var url6 = "get_ports_graph";
                  xmlhttp_get_ports_graph.open("GET", url6, true);
                  xmlhttp_get_ports_graph.send();
                  var url7 = "get_txids_graph";
                  xmlhttp_get_txids_graph.open("GET", url7, true);
                  xmlhttp_get_txids_graph.send();
              }
		else {
			document.getElementById("need_to_scan").style.visibility = "visible";
                        document.getElementById("hr0").style.visibility = "hidden";
                        document.getElementById("hr1").style.visibility = "hidden";
                        document.getElementById("hr2").style.visibility = "hidden";
                        document.getElementById("hr3").style.visibility = "hidden";
                        document.getElementById("hr4").style.visibility = "hidden";
                        document.getElementById("hr5").style.visibility = "hidden";
                        document.getElementById("hr6").style.visibility = "hidden";
		}
	}
}
      url0 = "is_scan_done";
      xmlhttp_is_scan_done.open("GET", url0, true);
      xmlhttp_is_scan_done.send();
      url8 = "count_entries"
      xmlhttp_total_entries.open("GET", url8, true);
      xmlhttp_total_entries.send();






	  
	  
	  
      // Set a callback to run when the Google Visualization API is loaded.
