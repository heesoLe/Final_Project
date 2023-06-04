/**
 * 
 */
 
function myPagePayment_addr(){
	//$('#addr_no').click(function(e) {
	   var addr_no =  $('#addr_no').val();

  $.ajax({//$는 jQuery란 뜻. $.ajax 뜻은 jQuery 내의 아작스 실행
      url:"/myPagePayment_addr", //url 패턴 매핑주소 경로
      type:"POST",//데이터를 서버로 보내는 방법
      data: {
      	"addr_no" : addr_no
      },  //좌측 id 피라미터 이름에 우측 $mem_id변수값을 저장
      datatype: "json",//서버의 실행된 결과값을 사용자로 받아오는 자료형
		traditional : true,
      success: function (res) {	
      alert('성공?');
		 for(let i = 0; i < res.length; i++){
			
  		 }
	  }
    });//$.ajax
    	//  });
/* end */	
//});
}

function test(){
var cart_no =  $('#cart_no').val();
alert(cart_no);
    $.ajax({
				
        type: 'POST',
        url: '/cart_cntUp',
        data:{
        "cart_no" : cart_no
        },
        dataType: 'json',
        success: function(obj) {
             
        },
        error: function(a, b, c) {
            console.log(a, b, c);
        }
				
    });

}