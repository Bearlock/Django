// Function to switch between prism.js stylesheets; gets all stylesheets except
// those that have a title attribute, since it assumes those are sitewide
// end result is that it disables all stylesheets except the one you picked. 
function styleSwitch(cssFile) {
	var linkTag
	for (var i=0, linkTag = document.getElementsByTagName("link"); i < linkTag.length; i++) {
		if (linkTag[i].rel.indexOf("stylesheet") != -1 && linkTag[i].title) {
			if (linkTag[i].title != cssFile) {
				linkTag[i].disabled = true;
			}
			else {
				linkTag[i].disabled = false;
			}
		}
	}
}

// Here we get the stylesheets and their buttons. For my purposes, if the 
// element tag '<code>' is not present on the page, the stylesheet buttons
// get removed. Otherwise, the end result is that the button you click
// will be the stylesheet that gets activated
var light   = document.getElementById("lightTheme");
var dark    = document.getElementById("darkTheme");
var buttons = document.getElementById("themeButtons");

if(document.getElementsByTagName("code").length == 0) {
	buttons.removeChild(dark);
	buttons.removeChild(light);
}

else {
	dark.onclick  = function() {  styleSwitch("dark");  }
	light.onclick = function() {  styleSwitch("light"); }
}

