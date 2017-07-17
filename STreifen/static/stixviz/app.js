// Init some stuff
// MATT: For optimization purposes, look into moving these to local variables
/*
uploader = document.getElementById('uploader');
*/
selectedContainer = document.getElementById('selection');
canvasContainer = document.getElementById('canvas-container');
canvas = document.getElementById('canvas');
//styles = window.getComputedStyle(canvas);

/* ******************************************************
 * Resizes the canvas based on the size of the window
 * ******************************************************/
function resizeCanvas() {
  //var cWidth = document.getElementById('legend').offsetLeft - 100;
  //var cHeight = window.innerHeight - document.getElementsByTagName('h1')[0].offsetHeight - 150;
  var cWidth = window.innerWidth * 5 / 10;
  var cHeight = window.innerHeight * 7 / 10;
  document.getElementById('canvas-wrapper').style.width = cWidth + "px";
  canvas.style.width = cWidth + "px";
  canvas.style.height = cHeight + "px";
}

/* ******************************************************
 * Will be called right before the graph is built.
 * ******************************************************/
function vizCallback() {
  hideMessages();
  resizeCanvas();
}

/* ******************************************************
 * Initializes the graph, then renders it.
 * ******************************************************/
function vizStixWrapper(content) {
  vizInit(canvas, {}, populateLegend, populateSelected);
  vizStix(content, vizCallback);
}

/* ----------------------------------------------------- *
 * ******************************************************
 * This group of functions is for handling file "upload."
 * They take an event as input and parse the file on the
 * front end.
 * ******************************************************/
function handleFileSelect(evt) {
  handleFiles(evt.target.files);
}
function handleFileDrop(evt) {
  evt.stopPropagation();
  evt.preventDefault();

  handleFiles(evt.dataTransfer.files);
}
function handleDragOver(evt) {
  evt.stopPropagation();
  evt.preventDefault();
  evt.dataTransfer.dropEffect = 'copy'; // Explicitly show this is a copy.
}
function handleFiles(files) {
  // files is a FileList of File objects (in our case, just one)
  for (var i = 0, f; f = files[i]; i++) {
    document.getElementById('chosen-files').innerText += f.name + " ";

    var r = new FileReader();
    r.onload = function(e) {vizStixWrapper(e.target.result)};
    r.readAsText(f);
  }
  linkifyHeader();
}
/* ---------------------------------------------------- */

/* ******************************************************
 * Handles content pasted to the text area.
 * ******************************************************/
function handleTextarea(id) {
  content = document.getElementById(id).value;
  vizStixWrapper(content)
  resizeCanvas();
  //linkifyHeader();
}

/* ******************************************************
 * Fetches STIX 2.0 data from an external URL (supplied
 * user) via AJAX. Server-side Access-Control-Allow-Origin
 * must allow cross-domain requests for this to work.
 * ******************************************************/
function handleFetchJson() {
  var url = document.getElementById("url").value;
  fetchJsonAjax(url, function(content) {
    vizStixWrapper(content)
  });
  linkifyHeader();
}

/* ******************************************************
 * Adds icons and information to the legend.
 *
 * Takes an array of type names as input
 * ******************************************************/
function populateLegend(typeGroups) {
  var ul = document.getElementById('legend-content');
  typeGroups.forEach(function(typeName) {
    var li = document.createElement('li');
    var val = document.createElement('p');
    var key = document.createElement('div');
    key.style.backgroundImage = "url('/static/icons/stix2_" + typeName.replace(/\-/g, '_') + "_icon_tiny_round_v1.png')";
    val.innerText = typeName.charAt(0).toUpperCase() + typeName.substr(1).toLowerCase(); // Capitalize it
    li.appendChild(key);
    li.appendChild(val);
    ul.appendChild(li);
  });
}

/* ******************************************************
 * Adds information to the selected node table.
 *
 * Takes datum as input
 * ******************************************************/
function populateSelected(d) {
  // Remove old values from HTML
  selectedContainer.innerHTML = "";
  
  var counter = 0;

  Object.keys(d).forEach(function(key) { // Make new HTML elements and display them
    // Create new, empty HTML elements to be filled and injected
    var div = document.createElement('div');
    var type = document.createElement('div');
    var val = document.createElement('div');
    
    // Assign classes for proper styling
    if ((counter % 2) != 0) {
      div.classList.add("odd"); // every other row will have a grey background
    }
    type.classList.add("type");
    val.classList.add("value");

    // Add the text to the new inner html elements
    var value = d[key];
    type.innerText = key;
    val.innerText = value;
    
    // Add new divs to "Selected Node"
    div.appendChild(type);
    div.appendChild(val);
    selectedContainer.appendChild(div);

    // increment the class counter
    counter += 1;
  });
}

/* ******************************************************
 * Hides the data entry container and displays the graph
 * container
 * ******************************************************/
function hideMessages() {
  //uploader.classList.toggle("hidden");
  canvasContainer.classList.toggle("hidden");
}

/* ******************************************************
 * Turns header into a "home" "link"
 * ******************************************************/
function linkifyHeader() {
  var header = document.getElementById('header');
  header.classList.add('linkish');
}

 /* *****************************************************
  * Returns the page to its original load state
  * *****************************************************/
function toggleViz(id) {
  var header = document.getElementById('canvas-container');
  //if (header.classList.contains('linkish')) {
  if (header.classList.contains('hidden')) {
    handleTextarea(id);
  }else{
    hideMessages();
    vizReset();
    //document.getElementById('files').value = ""; // reset the files input
    //document.getElementById('chosen-files').innerHTML = ""; // reset the subheader text
    document.getElementById('legend-content').innerHTML = ""; // reset the legend in the sidebar

    //header.classList.remove('linkish');
  }
}

/* ******************************************************
 * Generic AJAX 'GET' request.
 * 
 * Takes a URL and a callback function as input.
 * ******************************************************/
function fetchJsonAjax(url, cfunc) {
  var xhttp;
  if (window.XMLHttpRequest) {
    xhttp = new XMLHttpRequest();
  } else {
    xhttp = new ActiveXObject("Microsoft.XMLHTTP"); // For IE5 and IE6 luddites
  }
  xhttp.onreadystatechange = function() {
    if (xhttp.readyState == 4 && xhttp.status == 200) {
      cfunc(xhttp.responseText);
    }
  }
  xhttp.open("GET", url, true);
  xhttp.send();
}

function selectedNodeClick() {
  selected = document.getElementById('selected');
  if (selected.className.indexOf('clicked') === -1) {
    selected.className += " clicked";
    //selected.style.position = 'absolute';
    selected.style.left = '25px';
    selected.style.width = window.innerWidth - 110;
    selected.style.top = document.getElementById('legend').offsetHeight + 25;
    //selected.scrollIntoView(true);
  } else {
    selected.className = "sidebar"
    selected.removeAttribute("style")
  }
}

/* ******************************************************
 * When the page is ready, setup the visualization and bind events
 * ******************************************************/
// document.addEventListener("DOMContentLoaded", function(event) { 
window.onload = function() { 
  vizInit(canvas, {}, populateLegend, populateSelected);
  /*
  document.getElementById('paste-parser').addEventListener('click', handleTextarea, false);
  document.getElementById('header').addEventListener('click', resetPage, false);
  */
  document.getElementById('header').addEventListener('click', toggleViz, false);
  document.getElementById('selected').addEventListener('click', selectedNodeClick, false);
  window.onresize = resizeCanvas;
};
