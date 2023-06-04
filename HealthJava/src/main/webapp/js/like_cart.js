$('#like_cart').on('click', '.like', function(e) {
  var kind = $(e.target).attr('data-tab');
  var url = window.location.href;
  var product_no = url.substring(url.lastIndexOf('/') + 1);

  $.ajax({
    type: 'POST',
    url: '/product/like',
    data: {
      "kind": kind,
      "product_no": product_no
    },
    dataType: 'json',
    success: function(data) {
		
		if(data == 1) {
		
      alert('로그인을 해야합니다');
      
      }
      
      if(data == 2 ) {
      $('#like_cart').empty();

      const html = `
        
          <a class="like2" data-tab="2">찜 취소</a>
        
         <a data-tab="3" class="cart">장바구니</a>
        
      `;

      $('#like_cart').append(html);
    }},
    error: function(xhr, status, error) {
      console.log('Error:', error);
    }
  });
});

$('#like_cart').on('click', '.like2', function(e) {
  var kind = $(e.target).attr('data-tab');
  var url = window.location.href;
  var product_no = url.substring(url.lastIndexOf('/') + 1);

  $.ajax({
    type: 'POST',
    url: '/product/like',
    data: {
      "kind": kind,
      "product_no": product_no
    },
    dataType: 'json',
    success: function() {
      
      $('#like_cart').empty();

      const html = `
        
          <a class="like" data-tab="1">찜 하기</a>
        
          <a data-tab="3" class="cart">장바구니</a>
        
      `;
      $('#like_cart').append(html);
    },
    error: function(xhr, status, error) {
      console.log('Error:', error);
    }
  });
});

$('#like_cart').on('click', '.cart', function(e) {
  var kind = $(e.target).attr('data-tab');
  var url = window.location.href;
  var product_no = url.substring(url.lastIndexOf('/') + 1);

	var numTag = document.getElementById('num');
    var cart_cnt = numTag.innerHTML;


  $.ajax({
    type: 'POST',
    url: '/product/like',
    data: {
      "kind": kind,
      "product_no": product_no,
      "cart_cnt":cart_cnt
    },
    dataType: 'json',
    success: function(data) {
      
      if(data ==3) {
		  alert('장바구니 등록되었습니다.')
	  }
	  
	  if(data ==5) {
		  alert('로그인을 해야합니다.')
	  }
    },
    error: function(xhr, status, error) {
      console.log('Error:', error);
    }
  });
});


$('#buy').on('click', '.psbtn', function(e) {
 var kind = $(e.target).attr('data-tab');
  var url = window.location.href;
  var product_no = url.substring(url.lastIndexOf('/') + 1);

	var numTag = document.getElementById('num');
    var cart_cnt = numTag.innerHTML;
	
  $.ajax({
    type: 'POST',
    url: '/product/like',
    data: {
		
     "kind": kind,
      "product_no": product_no,
      "cart_cnt":cart_cnt
    },
    dataType: 'json',
    success: function(data) {
		
      
      if(data ==4) {
		  //alert('구매 등록됨.')
		  location.href="/PaymentOK";
	  }
	  
	  if(data ==5) {
		  alert('로그인을 해야합니다.')
	  }
    },
    error: function(xhr, status, error) {
      console.log('Error:', error);
    }
  });
});