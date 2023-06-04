<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<script src="https://code.jquery.com/jquery-3.6.3.js"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<script	src="../js/mypage.js"></script>
<title>HealthJava 장바구니</title>

<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.6.3/css/all.css" integrity="sha384-UHRtZLI+pbxtHCWp1t77Bi1L4ZtiqrqD80Kn4Z8NTSRyMA2Fd33n5dQ8lWUE00s/" crossorigin="anonymous">

<style type="text/css">
	/* 폰트 CSS */
	@font-face {
		font-family: 'KIMM_Bold';
		src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_2212@1.0/KIMM_Bold.woff2') format('woff2'); /* CDN 절대링크  */
		font-weight: 700;
		font-style: normal;
	}
	/* 되도록 안건드리는 영역 */
	* {
		box-sizing: border-box;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
		font-family: 'KIMM_Bold', sans-serif;
	}
	
	html {
		height: 100%;
	}
	
	body {
		margin: 0px;
		height: 100%;
		padding: 0px;
	}
	
	header {
		width: 100%;
		position: fixed;
		z-index: 2;
	}
	
	footer {
		bottom: 0;
		z-index: 5;
		position: relative;
	}
	
	.wrap {
		margin-top: -110px;
		min-height: 100%;
		position: relative;
	}
	
	.main {
		width: 1600px;
		height: 1200px;
		/* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 / section이랑 px 맞춰야함 */
		position: relative;
		top: 105px;
		left: 50%;
		transform: translateX(-50%);
	}
	
	section {
		height: 1200px;
	}
	/* 클리어 */
	.clear {
		clear: both;
	}
	/* 밑의 영역부터 css시작 */
	.container {
		width: 100%;
	}
	
	/******************/
	p {
		margin: 0.75rem 0 0;
	}
	
	input, button {
		border: 0 none;
		outline: 0 none;
	}
	
	.summary-checkout button {
		background-color: #666;
		color: #fff;
	}
	
	.summary-checkout button:hover, .summary-checkout button:focus {
		background-color: #555;
	}
	
	.product-image img, .basket-labels, .basket-product {
		width: 100%;
	}
	
	input, .summary-checkout button, .basket, .basket-module, .basket-labels,
		.item, .price, .quantity, .subtotal, .basket-product, .product-image,
		.product-details {
		float: left;
	}
	
	.hide {
		display: none;
	}
	
	main {
		clear: both;
		font-size: 0.75rem;
		margin: 0 auto;
		overflow: hidden;
		padding: 1rem 0;
		width: 960px;
	}
	
	.basket, .aside_right {
		padding: 0 1rem;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
		box-sizing: border-box;
	}
	/* 장바구니 전체 틀 */
	.basket {
	    width: 800px;
	    padding-bottom: 20px;
	    height: 850px;
	    margin: 0px 20px;
	}
	
	.basket-module {
		color: #111;
	}
	
	label {
		display: block;
		margin-bottom: 0.3125rem;
	}
	
	.promo-code-field {
		border: 1px solid #ccc;
		padding: 0.5rem;
		text-transform: uppercase;
		transition: all 0.2s linear;
		width: 48%;
		-webkit-box-shadow: inset 0 1px 1px rgba(0, 0, 0, .075);
		-moz-box-shadow: inset 0 1px 1px rgba(0, 0, 0, .075);
		-o-box-shadow: inset 0 1px 1px rgba(0, 0, 0, .075);
		box-shadow: inset 0 1px 1px rgba(0, 0, 0, .075);
	}
	
	.promo-code-field:hover, .promo-code-field:focus {
		border: 1px solid #999;
	}
	
	.promo-code-cta {
		border-radius: 4px;
		font-size: 0.625rem;
		margin-left: 0.625rem;
		padding: 0.6875rem 1.25rem 0.625rem;
	}
	
	.basket-labels {
		border-top: 1px solid #ccc;
		border-bottom: 1px solid #ccc;
		margin-top: 1.625rem;
	}
	
	.basket-labels ul {
		list-style: none;
		margin: 0;
		padding: 0;
	}
	
	.basket-labels li {
		color: #111;
		display: inline-block;
		padding: 0.625rem 0;
	}
	
	.basket-labels li.price:before, .basket-labels li.subtotal:before {
		content: '';
	}
	
	.item {
		width: 55%;
	}
	
	.price, .subtotal {
		width: 15%;
	}
	
	.subtotal {
		text-align: right;
	}
	
	.remove {
		bottom: 1.125rem;
		float: right;
		position: absolute;
		right: 0;
		text-align: right;
		width: 45%;
	}
	
	.remove button {
		background-color: transparent;
		color: #777;
		float: none;
		text-decoration: underline;
		text-transform: uppercase;
	}
	
	.remove button:hover {
		cursor: pointer;
	}
	
	.item-heading {
		padding-left: 4.375rem;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
		box-sizing: border-box;
	}
	
	.basket-product {
		border-bottom: 1px solid #ccc;
		padding: 15px 20px;
		position: relative;
	}
	
	.product-image {
		width: 90px;
	}
	
	.product-frame {
		border: 1px solid #aaa;
	}
	
	.product-details {
		padding: 0 1.5rem;
		-webkit-box-sizing: border-box;
		-moz-box-sizing: border-box;
		box-sizing: border-box;
		width: 450px;
		padding-left: 5px;
		text-align: left;
	}
	
	.quantity-field {
		background-color: #ccc;
		border: 1px solid #aaa;
		border-radius: 4px;
		font-size: 0.625rem;
		padding: 2px;
		width: 3.75rem;
		height: 20px;
		margin-left: 30px;
	}
	
	.aside_right {
		float: right;
		position: fixed;
		width: 30%;
		padding-left: 830px;
	}
	
	.summary {
		background-color: #eee;
		border: 1px solid #aaa;
		padding: 1rem;
		position: fixed;
		width: 250px;
		-moz-box-sizing: border-box;
		box-sizing: border-box;
		margin-top: 25px;
		margin-left: 50px;
	}
	
	.summary-total-items {
		color: #666;
		font-size: 0.875rem;
		text-align: center;
	}
	
	.summary-subtotal, .summary-total {
		border-top: 1px solid #ccc;
		border-bottom: 1px solid #ccc;
		clear: both;
		margin: 1rem 0;
		overflow: hidden;
		padding: 0.5rem 0;
	}
	
	.subtotal-title, .subtotal-value, .total-title, .total-value,
		.promo-title, .promo-value {
		color: #111;
		float: left;
		width: 50%;
	}
	
	.summary-promo {
		-webkit-transition: all .3s ease;
		-moz-transition: all .3s ease;
		-o-transition: all .3s ease;
		transition: all .3s ease;
	}
	
	.promo-title {
		float: left;
		width: 70%;
	}
	
	.promo-value {
		color: #8B0000;
		float: left;
		text-align: right;
		width: 30%;
	}
	
	.summary-delivery {
		padding-bottom: 3rem;
	}
	
	.subtotal-value, .total-value {
		text-align: right;
	}
	
	.total-title {
		font-weight: bold;
		text-transform: uppercase;
	}
	
	.summary-checkout {
		display: block;
	}
	
	.checkout-cta {
		display: block;
		float: none;
		font-size: 0.75rem;
		text-align: center;
		text-transform: uppercase;
		padding: 0.625rem 0;
		width: 100%;
	}
	
	.summary-delivery-selection {
		background-color: #ccc;
		border: 1px solid #aaa;
		border-radius: 4px;
		display: block;
		font-size: 0.625rem;
		height: 34px;
		width: 100%;
	}
	
	.total-title {
		text-align: left;
	}
	
	.aside_left {
		margin-top: 45px;
		margin-left: 60px;
		width: 180px;
		min-height: 700px;
		float: left;
		text-align: left;
	}
	
	.aside_left nav {
		min-height: 600px;
		margin-bottom: 50px;
	}
	
	.aside_left li {
		padding-top: 8.2px;
		padding-bottom: 2px;
		list-style: none;
	}
	
	#subspan {
		color: #808080;
	}
	
	.memBasicInfo1 {
		height: 120px;
		width: 120px;
		padding: 20px;
		float: left;
		margin-right: 200px;
		margin-top: 0px;
	}
	
	.memBasicInfo2 {
		height: 80px;
		width: 130px;
		position: relative;
		top: -40%;
		left: 50%;
	}
	
	.innerWrap {
		width: 300px;
		height: 220px;
		padding: 20px;
		float: left;
		margin-left: 60px;
		overflow: hidden;
	}
	
	#mypageTitle {
		font-size: 28px;
		font-weight: 700;
	}
	
	.mypageTitlebox {
		float: left;
		margin: 20px 0px 0px 5px;
	}
	
	#user_id {
		font-size: 20px;
		font-weight: 700;
	}
	/* 찜 목록 */
	.wishBox {
		margin-left: 0;
		width: 1200px;
		position: relative;
		left: 40%;
		top: 4%;
		transform: translateX(-50%);
		overflow: hidden;
		border-bottom: 2px solid rgb(217, 217, 217);
	}
	/* 찜한 상품 */
	#listTitle {
		font-size: 1.8em;
		font-weight: bold;
		margin-left: 15px;
	}
	
	.listTitleBox {
		width: 100%;
		height: 60px;
		border-bottom: 2px solid rgb(217, 217, 217);
		text-align: left;
	}
	
	/* a 링크 : 메뉴바 */	
	a:link.liList {
		text-decoration: none;
		color: #a399a2;
	}
	
	a:visited.liList {
		text-decoration: none;
		color: #a399a2;
	}
	
	a:hover.liList{
		text-decoration: underline;
		color: #B21948;
	}
	
	a:active.liList {
		text-decoration: none;
		color: #B21948;
	}
	/* 페이징 처리 */
	/* 페이징 전체 틀 */
	.pagination-container {
		margin: 10px auto;
		display: flex;
	    justify-content: center;
	}
	
	.pagination {
		position: relative;
	}
	/* 'PREV' 전체 틀 */
	#pagination a {
		position: relative;
		display: inline-block;
		color: #B21948; /* 글자색상 */
		text-decoration: none;
		font-size: 1.2rem;
		padding: 8px 16px 10px;
	}
	/* 'PREV' 부분 */
	#pagination a:before {
		z-index: -1;
		position: absolute;
		height: 100%;
		width: 100%;
		content: "";
		top: 0;
		left: 0;
		background-color: #B21948;
		border-radius: 24px;
		-webkit-transform: scale(0);
		transform: scale(0);
		transition: all 0.2s;
	}
	#pagination a:hover, #pagination a #pagination-active {
		color: #fff;
	}
	
	#pagination a:hover:before, #pagination a #pagination-active:before {
		-webkit-transform: scale(1);
		transform: scale(1);
	}
	
	#pagination #pagination-active {
		color: #fff;
	}
	
	#pagination #pagination-active:before {
		-webkit-transform: scale(1);
		transform: scale(1);
	}
	/*'NEXT' 전체 틀 */
	#pagination-newer {
		margin-right: 50px;
	}
	
	#pagination-older {
		margin-left: 50px;
	}
	.productList tr{
		border-bottom: 1px solid #B21948;
	}
	.meau {
		padding-top: 30px;
		padding-left: 800px;
		font-family: 'KIMM_Bold';
	}
	
	.meau a {
		color: white;
		text-decoration: none;
	}
	select {
		padding : 5px 5px;
	}
	
	/*추가*/
	
.basketdiv {
    width: 100%;
    border-top: 1px solid #e0e0e0;
    float: left;
    font-size: 0.9375em;
    margin-bottom: 20px;
}
   .basketdiv .row.head {
        border-bottom: 2px solid #888;
        box-sizing: border-box;
        background-color: #f4f4f4;
        font-weight: 500;
    }
    .basketdiv .data {
        border-bottom: 1px dashed #888;
        box-sizing: border-box;
        cursor: pointer;
        float: left;
        width: 100%;
    }
    .basketdiv .data .empty{
        text-align: center;
        padding: 12px 0;
    }
    .basketdiv .row.head .subdiv {
        background-color: #f4f4f4;
    }
    .basketdiv .row > .subdiv {
        display: block;
        float: left;
    }
    .basketdiv .row > .subdiv:nth-child(1) {
        width: 50%;
    }
    .basketdiv .row > .subdiv:nth-child(2) {
        width: 40%;
    }
    .basketdiv .row > .subdiv:nth-child(3) {
        width: 10%;
    }
    .basketdiv2 .row > .subdiv:nth-child(1) {
        width: 60%;
    }
    .basketdiv2 .row > .subdiv:nth-child(2) {
        width: 40%;
    }
    .basketdiv .row > div > div {
        display: block;
        float: left;
        text-align: center;
        margin: 0;
        padding: 12px 0;
    }
    .basketdiv .row.data > div > div {
        height: 60px;
        line-height: 60px;
    }
        .basketdiv .data .num .updown {
            color: #0075ff;
            font-size: 2em;
            letter-spacing: -5px;
        }
        .basketdiv .check {
            width: 10%;
        }
    .basketdiv .check input[type=checkbox] {
        transform: scale(1.5);
    }
    .basketdiv .img{
        width: 20%;
    }
    .basketdiv .pname{
        width: 70%;
    }
    .basketdiv2 .pname {
        width: 80%;
    }
    .basketdiv .basketprice {
        width: 33%;
    }
    .basketdiv .num {
        width: 33%;
      min-width: 105px;
    }
    .basketdiv .sum {
        width: 34%;
      max-width: 80px;
        color: #0000aa;
    }
    .basketdiv .point {
        width: 50%;
    }
    .basketdiv2 .basketprice {
        width: 25%;
    }

    .basketdiv2 .num {
        width: 25%;
    }

    .basketdiv2 .sum {
        width: 25%;
        color: #0000aa;
    }

    .basketdiv2 .point {
        width: 25%;
    }
    .basketdiv .basketcmd{
        width: 100%;
    }
    .basketdiv .data .pname {
        text-align: left !important;
      line-height: 1.2 !important;
    }
    .basketdiv .data .price, .basketdiv .data .sum, .basketdiv .data .point {
        text-align: right;
    }
    .baseform > tbody > tr > td:first-child {
        width: 100px;
    }

.buttongroup {
    padding: 11px 0;
    margin: 50px 0;
}
.narrowbuttongroup{
    margin: 15px 0;
}
    .buttongroup.center {
        text-align: center;
    }
    .buttongroup input[type=text], .buttongroup input[type=password] {
        height: 30px;
    }
    .buttongroup button, .buttongroup a {
        margin-right: 5px;
    }
        .buttongroup button:last-child, .buttongroup a:last-child {
            margin-right: 0;
        }

    .abutton, .abutton:link, .abutton:visited, .abutton:active, input[type=button] {
        background-color: #383838;
        border: 1px solid #888888;
        color: #ffffff;
        cursor: pointer;
        letter-spacing: -1px;
        padding: 3px 5px;
        margin: 2px 3px;
        width: auto;
        word-break: keep-all;
        border-radius: 5px;
        text-decoration: none;
        font-size: 0.9375em;
    }

.abutton-alt {
    background-color: #d3e2c6;
}

.red {
    color:#b00;
}
.blue {
  color: #0075ff;
}
.basketrowcmd, .sumcount, .summoney{
  text-align: right;
  margin-bottom: 10px;
}
.sumcount, .summoney{
  font-size: 1.25em;
    font-weight: bold;
}
.buttongroup{
  text-align: center;
}
.buttongroup a{
  text-decoration: none;
}
.cmd a, .cmd span {
    padding: 12px 30px;
    box-sizing: border-box;
    margin-top: 10px;
    font-size: 1.2em;
    color: #000;
    background-color: #f4f4f4;
    border: 1px solid #e0e0e0;
    text-align: center;
}
.cmd.small a, .cmd.small span {
    padding: 6px 20px;
    font-size: 0.8125em;
}

.orderform .p_num {
    text-align: right;
    width: 40px;
    font-size: 1em;
}
	
</style>

<script type="text/javascript">
let basket = {
    totalCount: 0, 
    totalPrice: 0,
    //체크한 장바구니 상품 비우기
    delCheckedItem: function(){
        document.querySelectorAll("input[name=buy]:checked").forEach(function (item) {
            item.parentElement.parentElement.parentElement.remove();
        });
        //AJAX 서버 업데이트 전송
    
        //전송 처리 결과가 성공이면
        this.reCalc();
        this.updateUI();
    },
    //장바구니 전체 비우기
    delAllItem: function(){
        document.querySelectorAll('.row.data').forEach(function (item) {
            item.remove();
          });
          //AJAX 서버 업데이트 전송
        
          //전송 처리 결과가 성공이면
          this.totalCount = 0;
          this.totalPrice = 0;
          this.reCalc();
          this.updateUI();
    },
    //재계산
    reCalc: function(){
        this.totalCount = 0;
        this.totalPrice = 0;
        document.querySelectorAll(".p_num").forEach(function (item) {
            if(item.parentElement.parentElement.parentElement.previousElementSibling.firstElementChild.firstElementChild.checked == true){
                var count = parseInt(item.getAttribute('value'));
                this.totalCount += count;
                var price = item.parentElement.parentElement.previousElementSibling.firstElementChild.getAttribute('value');
                this.totalPrice += count * price;
            }
        }, this); // forEach 2번째 파라메터로 객체를 넘겨서 this 가 객체리터럴을 가리키도록 함. - thisArg
    },
    //화면 업데이트
    updateUI: function () {
        document.querySelector('#sum_p_num').textContent = '상품갯수: ' + this.totalCount.formatNumber() + '개';
        document.querySelector('#sum_p_price').textContent = '합계금액: ' + this.totalPrice.formatNumber() + '원';
    },
    //개별 수량 변경
    changePNum: function (pos) {
        var item = document.querySelector('input[name=p_num'+pos+']');
        var p_num = parseInt(item.getAttribute('value'));
        var newval = event.target.classList.contains('up') ? p_num+1 : event.target.classList.contains('down') ? p_num-1 : event.target.value;
        
        if (parseInt(newval) < 1 || parseInt(newval) > 99) { return false; }

        item.setAttribute('value', newval);
        item.value = newval;

        var price = item.parentElement.parentElement.previousElementSibling.firstElementChild.getAttribute('value');
        item.parentElement.parentElement.nextElementSibling.textContent = (newval * price).formatNumber()+"원";
        //AJAX 업데이트 전송

        //전송 처리 결과가 성공이면    
        this.reCalc();
        this.updateUI();
    },
    checkItem: function () {
        this.reCalc();
        this.updateUI();
    },
    delItem: function () {
        event.target.parentElement.parentElement.parentElement.remove();
        this.reCalc();
        this.updateUI();
    }
    

}

// 숫자 3자리 콤마찍기
Number.prototype.formatNumber = function(){
    if(this==0) return 0;
    let regex = /(^[+-]?\d+)(\d{3})/;
    let nstr = (this + '');
    while (regex.test(nstr)) nstr = nstr.replace(regex, '$1' + ',' + '$2');
    return nstr;
};

  
</script>

</head>
<body>
	<%-- 전체 영역 --%>
	<div class="wrap">
		<%-- 헤더 영역 --%>
		<header>
			<%-- header include --%>
			<jsp:include page="../include/header.jsp"/>
		</header>
		<%-- 메뉴바 --%>
		<section>
			<div class="main">
				<%-- main 화면 상단 캐러셀 (캐러셀 필요 없는 페이지는 삭제 바람!)--%>
				<aside class="aside_left">
					<nav>
						<ul>
							<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"><a href="myPage_Main" style="text-decoration: none; color: black;">나의 쇼핑</a></li>
							<li><a href="myPage_order" class="liList">주문ㆍ배송</a></li>
							<li><a href="myPage_like" class="liList">찜 목록</a></li>
							<li><a href="myPage_cart" class="liList" style="color: #B21948;">장바구니</a></li>
							<li><a href="myPage_review" class="liList">나의 상품후기</a></li>
	
							<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 회원 정보</li>
							<li><a href="myPage_updateInfo" class="liList">회원정보 변경</a></li>
							<li><a href="myPage_changePwd" class="liList">비밀번호 변경</a></li>
							<li><a href="myPage_user_Withdrawal" class="liList">회원탈퇴</a></li>
							<li style="margin-bottom: 30px;"><a href="myPage_updateAddress" class="liList">배송지 관리</a></li>
							
							<!-- <li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 나의 상품후기</li> -->
						</ul>
					</nav>
				</aside>
				
			<%-- 장바구니 --%>
			
			<div class="wishBox">
				<div class="listTitleBox">
					<span id="listTitle">장바구니</span>
				</div>
				<div class="basketcontentBox">
				
				<form action="myPagePayment" method="post">
				
					<div class="basketdiv" id="basket">
                <div class="row head">
                
                    <div class="subdiv">
                        <div class="check">선택</div>
                        <div class="img">이미지</div>
                        <div class="pname">상품명</div>
                    </div>
                    <div class="subdiv">
                        <div class="basketprice">가격</div>
                        <div class="num">수량</div>
                        <div class="sum">합계</div>
                    </div>
                    <div class="subdiv">
    
                        <div class="basketcmd">삭제</div>
                    </div>
                    <div class="split"></div>
                </div>
        		
       			<c:if test="${!empty clist }">
			    <c:forEach var="c" items="${clist }" varStatus="status">
                <div class="row data">
                    <div class="subdiv">
                        <div class="check"><input type="checkbox"  name="buy" value="${c.cart_no}" checked="" onclick="javascript:basket.checkItem();">&nbsp;</div>
                        <div class="img"><img src="/upload${c.product_cont1}" alt="${c.product_cont1}" width="60"></div>
                        <div class="pname">
                            <span><input type="text" name="product_title${c.cart_no}" value="${c.product_title}"></span>
                        </div>
                    </div>
                    <div class="subdiv">
                        <div class="basketprice">
                        <input type="hidden" name="product_price${c.cart_no}" id="p_price${status.count}" class="p_price" value="${c.product_price}">${c.product_price}원</div>
                        <div class="num">
                            <div class="updown">
                                <input type="text" name="p_num${status.count}" id="p_num${status.count}" size="2" maxlength="4" class="p_num" value="${c.cart_cnt}" onkeyup="javascript:basket.changePNum(${status.count});">
                           
                                <span onclick="javascript:basket.changePNum(${status.count});<%-- location='cart_cntUp?cart_no=${c.cart_no }' --%>"><i class="fas fa-arrow-alt-circle-up up"></i></span>
                                <span onclick="javascript:basket.changePNum(${status.count});<!-- test(); -->"><i class="fas fa-arrow-alt-circle-down down"></i></span>
                            </div>
                        </div>
                        <div class="sum">${c.product_price * c.cart_cnt }원</div>
                    </div>
                    <div class="subdiv">
                        <div class="basketcmd"><a class="abutton" onclick="location='cart_del?cart_no=${c.cart_no}';">삭제</a></div>
                    </div>
                </div>
                <c:set var="totalcount" value="${totalcount+c.cart_cnt }"/>
                <c:set var="totalprice" value="${totalprice+c.product_price*c.cart_cnt }" />
                </c:forEach>
                </c:if>
                <input type="hidden" name="totalprice" value="${totalprice}">
                
        
            </div>		   
				   <!-- 결제 창 -->
					<div class="right-align basketrowcmd">
                <!-- <a href="javascript:void(0)" class="abutton" onclick="javascript:basket.delCheckedItem();">선택상품삭제</a> -->
                <a href="javascript:void(0)" class="abutton" onclick="location='cart_delall';">장바구니비우기</a>
            </div>
    
            <div class="bigtext right-align sumcount" id="sum_p_num">상품갯수: ${totalcount}개</div>
            <div class="bigtext right-align box blue summoney" id="sum_p_price">합계금액:${totalprice}원</div>
   			
            <div id="goorder" class="">
                <div class="clear"></div>
                <div class="buttongroup center-align cmd">
                   <button type="submit"> <a>선택한 상품 주문</a></button>
                </div>
                
            </div>
            </form>
						</div>
						</div>
						</div>
						
	<!-- 			<script type="text/javascript">
				
				function price(){
					const element = document.getElementById('sum_p_price').textContent;
					$('.totalprice').val(element);
					$.ajax({
					    type : "POST",
					    url : "myPage_totalprice", 
					    data : "totalprice="+element,
					    error : function(error) {
					    	alert("error");
					    },
					    success : function(data) {
						alert("success"+element);
					    }
					});
				}
				</script> -->
				
				
				
				  
				   			
			<%-- top버튼 삭제 X --%>
			<div id="topBtn">
				<span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
			</div>
		</section>
		<div class="clear"></div>
		<%-- 푸터 영역 --%>
		<footer>
			<!-- footer -->
			<jsp:include page="../include/footer.jsp"/>
			<!-- footer 끝 -->
		</footer>
	</div>
	
	<script type="text/javascript">
	
		<%-- top버튼 부분 --%>
		// 클릭 이벤트 핸들러
		$("#topBtn").click(function(e) {
			e.stopPropagation();
			$("html, body").animate({
				scrollTop : 0
			}, 'fast', 'easeOutCubic');
		});

		// 스크롤 이벤트 핸들러
		$(window).scroll(function() {
			if ($(window).scrollTop() == 0) {
				$("#topBtn").css("opacity", 0); // TOP 버튼 숨기기
			} else {
				$("#topBtn").css("opacity", 1); // TOP 버튼 나타내기
			}
		});

	</script>
</body>
</html>