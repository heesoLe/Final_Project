/**
 * cs.js
 */

  function toggleContent(element) {
    // Find the next sibling element
	
    var content = element.nextElementSibling;
    
    // Toggle the "hidden" class
    content.classList.toggle("hidden");
    
   var rows = element.parentNode.children;
    
    for (var i = 0; i < rows.length; i++) {
      if (rows[i] !== content && i % 2 === 1) {
        rows[i].classList.add("hidden");
      }
    }

  }		  
  
