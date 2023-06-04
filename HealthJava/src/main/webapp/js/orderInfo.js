/**
 * 
 */

function order_check(){
	
	if($.trim($("#order_rec").val())==""){
		alert("수령인의 이름을 입력하세요!");
		$("#order_rec").val("").focus();
		return false;
	}

	if($.trim($("#postCode").val())==""){
		alert("우편번호를 입력하세요!");		
		return false;
	}
	if($.trim($("#roadAddr").val())==""){
		alert("주소를 입력하세요!");		
		return false;
	}

	if($.trim($("#user_phone").val())==""){
		alert("수령인의 핸드폰번호를 입력하세요!");
		$("#user_phone").val("").focus();
		return false;
	}
	
	alert("주문이 완료되었습니다!");
}

function heart(){
	
	alert("찜♡");

}

function cart(){
	alert("장바구니에 담았습니다!")
}
