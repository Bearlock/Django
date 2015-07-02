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

document.getElementById("darkTheme").onclick  = function() {  styleSwitch("dark");  }
document.getElementById("lightTheme").onclick = function() {  styleSwitch("light"); }