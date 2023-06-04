<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri= "http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-rbsA2VBKQhggwzxH7pPCaAqO46MgnOM80zW1RWuH61DGLwZJEdK2Kadq2F9CUG65" crossorigin="anonymous"> <%-- CDN 절대링크 --%>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="https://code.jquery.com/jquery-3.6.3.js"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>

<title>HealthJava 상품설명</title>

<style type="text/css">

#gume {
	    background: #b21949;
	    color: white;
	    font-size: 22px;
	    /* margin-left: 26px; */
	    display: table;
	    table-layout: fixed;
	    width: 100%;
	    height: 60px;
	    border: 3px solid black;
	    border-bottom: 1px solid black;
	    text-align: center;
	    -webkit-font-smoothing: subpixel-antialiased;
	    -webkit-text-size-adjust: none;
	    -webkit-tap-highlight-color: rgba(0,0,0,0);
}
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
		width: 1400px;
		height: auto; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 / section이랑 px 맞춰야함 */
		position : relative;
		top: 105px;
		left: 40%;
        transform: translateX( -50% );
        margin: 200px;
		
	}
	section {
		height: auto; /* UI 개발할 때 각 페이지에 맡게 해당 영역 px수치 수정해야함 / .main이랑 px 맞춰야함 */
		
	}
	/* 클리어 */
	.clear {
		clear: both;
	}
	/* 밑의 영역부터 css시작 */
	.container {
		width: 100%;
	}
	
	
	/*본문 css 시작*/


ul,li,body,h1,h2,h3,h4,h5,h6{margin: 0; padding: 0;}
	ul li{list-style: none;}
	a{text-decoration: none;}
	*{font-family: 'KIMM_Bold';}

	.shCMSshop{margin: 0;	padding: 60px 0 0 0;	width: 1200px; margin: 0 auto;}
	.shCMSshop .shopView .viewHeader:after{display: block; content: ''; clear: both;}
	.shCMSshop .shopView .viewHeader .productImg{float: left; }
	.shCMSshop .shopView .viewHeader .productImg .mainImg{
		width: 500px; 
		height:500px; 
		
	}
	.shCMSshop .shopView .viewHeader .productImg ul{margin-top: 35px;}
	.shCMSshop .shopView .viewHeader .productImg ul li{
		width: 85px; 
		height:85px; 
		background: #000; 
		display: inline-block;
		margin-right: 25px; 
		border:1px solid #ccc; 
		cursor: pointer;
	}
	.shCMSshop .shopView .viewHeader .productImg ul li:first-child{margin-left: 30px;}

	.shCMSshop .shopView .viewHeader .productInfo{margin-left: 50px; width: 600px; float:left;}
	.shCMSshop .shopView .viewHeader .productInfo h3{font-size: 23px;margin-bottom: 63px;}
	.shCMSshop .shopView .viewHeader .productInfo .price{border-bottom: 1px solid #e6e6e6;padding-bottom: 16px;}
	.shCMSshop .shopView .viewHeader .productInfo .price:after{display: block; content:''; clear: both;}
	.shCMSshop .shopView .viewHeader .productInfo .sale{font-size: 45px; font-family:'KIMM_Bold'; color:#e63740; font-weight: bold; float: left;}
	.shCMSshop .shopView .viewHeader .productInfo .sale span{font-size: 25px;}
	.shCMSshop .shopView .viewHeader .productInfo .cost-price{float: left; margin: 5px 0 0 20px; font-size: 15px; color: #5a5a5a; text-decoration: line-through;}
	.shCMSshop .shopView .viewHeader .productInfo .sale-price{float: left; margin: 15px 0 0 -55px; font-family: 'KIMM_Bold'; font-weight: bold; font-size: 25px;}

	.shCMSshop .shopView .viewHeader .productInfo .price~.star-ratings, .manufact, .categori, .origin{
		padding: 16px 0 16px 10px; 
		border-bottom: 1px solid #e6e6e6; 
		font-size: 18px; 
		white-space: pre;
		text-align: -webkit-auto;
	}
	.shCMSshop .shopView .viewHeader .productInfo .price~.star-ratings span, .manufact span, .categori span, .origin span{
		color:#6a6a6a;
	}
	.shCMSshop .shopView .viewHeader .productInfo .items{padding: 16px 0;}
	.shCMSshop .shopView .viewHeader .productInfo .items select{
		width: 630px; 
		height: 40px; 
		margin: 0 auto; 
		display: block; 
		border: 1px solid #cdcdcd;
		padding-left: 10px;
	}
	.shCMSshop .shopView .viewHeader .productInfo .item{
		padding: 16px 0 16px 10px; 
		border-bottom: 1px solid #e6e6e6; 
		position: relative;
		margin-left: 1px;
	}
	.shCMSshop .shopView .viewHeader .productInfo .item:after{display: block;content: '';clear: both;}
	.shCMSshop .shopView .viewHeader .productInfo .item a{width: 30px; height:30px; background: #f8f8f8; border: 1px solid #d8d8d8;box-sizing: border-box; display: inline-block;}
	.shCMSshop .shopView .viewHeader .productInfo .item .item-name{font-size: 16px; font-weight: 300;}
	.shCMSshop .shopView .viewHeader .productInfo .item .item-name+span{
		display: inline-flex; 
		margin-left: 30%;
	}
	.shCMSshop .shopView .viewHeader .productInfo .item .item-name+span a{
		font-size: 20px;
    	font-weight: bold;
		text-align: center center;
	}
	.shCMSshop .shopView .viewHeader .productInfo input[type="number"]{margin: 0 -1px;padding-top: 4px;width: 40px; border:1px solid #d8d8d8;text-align: right;}
	.shCMSshop .shopView .viewHeader .productInfo .item-price{font-family: 'KIMM_Bold'; font-weight: bold; font-size: 18px; margin-left: 20px;}
	.shCMSshop .shopView .viewHeader .productInfo .item-price+a{float:right; text-align: center; width: 30px; height: 30px; margin: 0px 10px 0 0; font-weight: bold; padding-bottom: 18px;}
	.shCMSshop .shopView .viewHeader .productInfo .all-price{margin-top: 55px; text-align: right; white-space: pre; font-size: 18px;}
	.shCMSshop .shopView .viewHeader .productInfo .all-price span{font-family: 'KIMM_Bold'; font-size: 25px; font-weight: bold; color: #e63740;}
	
	a { text-decoration: none!important; }
	
	.shCMSshop .shopView .viewHeader .productInfo .btn{
		text-align: right;
		margin-top: 40px;
		 -webkit-tap-highlight-color: rgba(0,0,0,0);
	}
	.shCMSshop .shopView .viewHeader .productInfo .btn a{
		padding: 15px 56px;
		font-size: 22px; 
		display: inline-block;
		 -webkit-tap-highlight-color: rgba(0,0,0,0);
	}
	.shCMSshop .shopView .viewHeader .productInfo .btn .first .psbtn{
	    background: #FC5400;
	    color: white;
	    font-size: 22px;
	    /* margin-left: 26px; */
	    display: table;
	    table-layout: fixed;
	    width: 100%;
	    border: 1px solid #FC5400;
	    text-align: center;
	    -webkit-font-smoothing: subpixel-antialiased;
	    -webkit-text-size-adjust: none;
	    -webkit-tap-highlight-color: rgba(0,0,0,0);
	}
	
	.shCMSshop .shopView .viewHeader .productInfo .btn .second a:first-child{
	    color: black;
	    border-top: 3px solid black;
	    border-right: 2px solid black;
	    border-left: 3px solid black;
	    border-bottom: 3px solid black;
	    background-color: white;
	    box-sizing: border-box;
	    display: table-cell;
	    table-layout: fixed;
	    width: 33%;
	    text-align: center;
	    -webkit-font-smoothing: subpixel-antialiased;
	    -webkit-text-size-adjust: none;
	    -webkit-tap-highlight-color: rgba(0,0,0,0);
	    display: table-cell;
	}
	.shCMSshop .shopView .viewHeader .productInfo .btn .second a:last-child{
	    color: black;
	    border: 3px solid black;
	    background-color: white;
	    display: table-cell;
	    table-layout: fixed;
	    width: 33%;
	    text-align: center;
	    -webkit-font-smoothing: subpixel-antialiased;
	    -webkit-text-size-adjust: none;
	    -webkit-tap-highlight-color: rgba(0,0,0,0);
	    display: table-cell;
	    border-left: 2px solid black;
	}
	
	/*
	<div class="XqRGHcrncz">
		<div class="_3YA58cPPsy">
			
			<div class="OgETmrvExa sys_chk_buy N=a:pcs.nbuy">
				<a href="#" class="_2-uvQuRWK5">
					<span class="blind">구매하기</span>
				</a>
			</div>
			
		</div>
		
		<div class="_3YA58cPPsy">
			
			<div class="_39-ECjV6I9 N=a:pcs.talk">
				<a href="#" role="button" class="H4-2Au4vay">
					<span class="blind">톡톡문의</span>
				</a>
			</div>
			
			<div class="_3Dy-2NaoiG N=a:pcs.mylist">
				<a href="#" role="button" class="_8ToEZI8a1P" aria-pressed="false">
					<span class="_1F0dbkDlNA">
						<span class="blind">찜하기</span>
					</span>
					<em class="_1c-2nfzJqH">114</em>
				</a>
			</div>
			
			<div class="C_muF3UG0- sys_chk_cart N=a:pcs.basket">
				<a href="#" role="button" class="_3g6Aiz5G_O">
					<span class="blind">장바구니</span>
				</a>
			</div>
		</div>
	</div>
*/
	.shCMSshop .shopView .viewBody{margin-top: 100px;}
	.shCMSshop .shopView .viewBody .contentNav:after{display: block;content:'';clear: both;}
	.shCMSshop .shopView .viewBody .contentNav li{
		width: 31%;
	    float: left;
	    background: #b21949;
	    border: 1px solid white;
	    box-sizing: border-box;
	    text-align: center;
	    margin-right: -1px;
	    font-size: 18px;
	}
	.shCMSshop .shopView .viewBody .contentNav a{
	    display: block;
    	padding: 20px 0px;
    	color: white;
    	background-color: #b21949;
    	border: 2px solid white;
    	
	}
	.shCMSshop .shopView .viewBody .contentNav a span{font-size: 15px;}
	.shCMSshop .shopView .viewBody .contentNav a span .count{font-size: 15px;}
	.shCMSshop .shopView .viewBody .contentNav li.active{background: #FC5400;}
	.shCMSshop .shopView .viewBody .contentNav li.active a{
	    color: white;
    	background-color: #FC5400;
	}

	/*테이블 기본 셋팅*/
	.shCMSshop .shopView .viewBody table{
	    border-top: 3px solid #b21949;
	    border-bottom: 1px solid #b21949;
	    width: 100%;
	    margin: 60px 0 40px 0;
	    border-collapse: collapse;
	    border-spacing: 0;
	    font-size: 14px;
	}
	.shCMSshop .shopView .viewBody thead>tr{
		height:40px;
		background: #F4A460; 
		text-align: center;
	}
	.shCMSshop .shopView .viewBody table tr{border-top:1px solid  lightgray;}
	.shCMSshop .shopView .viewBody table tr:first-child{border-top: none;}
	.shCMSshop .shopView .viewBody table .tcontent{text-align: left;}
	.shCMSshop .shopView .viewBody table .tcontent:hover{cursor: pointer;}
	.shCMSshop .shopView .viewBody table .tcontent:hover span{text-decoration: underline;}
	.shCMSshop .shopView .viewBody table .tcontent span{white-space: nowrap; overflow: hidden; text-overflow: ellipsis; width: 225px; display: inline-block;}
	/*상품 정보*/
	.shCMSshop .shopView .viewBody .tproduct-info tr:first-child{border-top:2px solid #5d5d5d;}
	.shCMSshop .shopView .viewBody .tproduct-info tr td{padding: 0 13px; line-height: 20px;}
	.shCMSshop .shopView .viewBody .tproduct-info tr td:first-child{
	    background: #F4A460;
	    height: 50px;
	    padding-left: 20px;
	    width: 16.5%;
	    color: black;
	}
	.shCMSshop .shopView .viewBody .tproduct-info tr td:nth-child(3){
	    background: #F4A460;
    	width: 16.5%;
    	padding-left: 20px;
    	color: black;
	}
	/*상품 후기*/
	.shCMSshop .shopView .viewBody .tproduct-review thead>tr>td:first-child{width: 130px; background: #F4A460; height: 40px;text-align: center;}
	.shCMSshop .shopView .viewBody .tproduct-review thead>tr>td:nth-child(3){width: 140px;}
	.shCMSshop .shopView .viewBody .tproduct-review thead>tr>td:last-child{width: 145px;text-align: center;}
	.shCMSshop .shopView .viewBody .tproduct-review tr{height: 50px; text-align: center;}
	/*상품 후기 더보기*/
	.shCMSshop .shopView .viewBody .tproduct-review .detail-content{display: none;}
	.shCMSshop .shopView .viewBody .tproduct-review .detail-content td:first-child{width: 130px;}
	.display{display:table-row!important;border-top:none!important;}
	.overflow{overflow:inherit!important;}
	.text{width: 207px!important; text-overflow: unset!important;}
	/*Q & A 테이블 감싸기 - 문의하기 버튼 넣기 용도*/
	.shCMSshop .shopView .viewBody .tquestion{position: relative;}
	.shCMSshop .shopView .viewBody .tquestion a{
		position: absolute; 
		right: 0; 
		top: -40px; 
		padding: 8px 12px; 
		background: #FC5400; 
		color: white; 
		font-size: 14px;
	}
	/*Q & A*/
	.shCMSshop .shopView .viewBody .tquestion thead>tr>td:first-child{
		width: 72px; 
		background: #F4A460; 
		height: 40px;
		text-align: center;
	}
	.shCMSshop .shopView .viewBody .tquestion thead>tr>td:nth-child(3){width: 140px;}
	.shCMSshop .shopView .viewBody .tquestion thead>tr>td:last-child{width: 145px;}
	.shCMSshop .shopView .viewBody .tquestion tr{text-align: center;}
	.shCMSshop .shopView .viewBody .tquestion tr{height: 40px;}
	.shCMSshop .shopView .viewBody .tquestion tr:first-child~tr td:nth-child(2){width: 95px;}
	.shCMSshop .shopView .viewBody .tquestion td.answer-no{color: #e63740;}
	.shCMSshop .shopView .viewBody .tquestion td.answer-ok{color: #3c43c7;}

	/*jquery용 테이블 셋팅*/
	.shCMSshop .shopView .viewBody table{display: none;}
	.shCMSshop .shopView .viewBody table.active{display: table;}


	li.subImg{
		margin-top: 100px; 
	}
	.shCMSshop .shopView .viewHeader .productImg .thumbnail-container {
    display: flex;
    flex-direction: row; /* 가로로 배치 */
    flex-wrap: wrap;
    justify-content: flex-start;
    align-items: flex-start;
    margin-top: 10px;
}
.MemList {
		border: none;
		width: 1300px;
		height: 250px;
		border-top: 2px solid #b21949;
		border-bottom: 2px solid #b21949;
		font-family: 'KIMM_Bold';
	}
	
	.MemList tr {
		border-bottom: 1px solid #b21949;

}
.hidden {
    display: none;
  }
</style>


<script>
/*
var plus = document.querySelector(".plus");
var minus = document.querySelector(".minur");
var result = document.querySelector("#num");
var totalcost = document.querySelector(".totalcost");
var i = 1;
plus.addEventListener("click",() => {
	i++;
	result.textContent = i;
	var totalcostNum = i * 13000;
	totalcost.textContent = totalcostNum.toLocaleString();
	
	
});

minus.addEventListener("click",() => {
	if(i > 0){
		i--;
		result.textContent = i;
		var totalcostNum = i * 13000;
		totalcost.textContent = totalcostNum.toLocaleString();
	} else {
		totalcost.textContent = 0;
	}
	
});
*/

var init = 1;
document.querySelector("#num").innerText = init;
var totalcost;

function plus() {
var	price = ${detail.product_price};

  init += 1;
  document.querySelector("#num").innerText = init;
  totalcost = ((price * init)).toLocaleString();
  document.querySelector(".totalcost").innerText = totalcost;
  //document.querySelector(".totalcost").innerText = init * price;
  
  //${totalcost}=totalcost;
  //alert(${totalcost});
  
}

function minus() {
	var	price = ${detail.product_price};
	
  init < 1 ? (init = 0) : (init -= 1);
  document.querySelector("#num").innerText = init;
  totalcost = ((price * init)).toLocaleString();
  document.querySelector(".totalcost").innerText = totalcost;
  //document.querySelector(".totalcost").innerText = init * price;
}

function sendPost(action) {
	if(init == 1){
		action = action + "&product_cnt=" + init + "&total_price=${detail.product_price}";
	}else{
		action = action + "&product_cnt=" + init + "&total_price=" + totalcost;
	}
	
    location=action;
	/*

	var form = document.createElement('form');

	form.setAttribute('method', 'post');

	form.setAttribute('action', action);

	document.charset = "utf-8";

	for ( var key in params) {

		var hiddenField = document.createElement('input');

		hiddenField.setAttribute('type', 'hidden');

		hiddenField.setAttribute('name', key);

		hiddenField.setAttribute('value', params[key]);

		form.appendChild(hiddenField);

	}

	document.body.appendChild(form);

	form.submit();
*/
}




/*
function price_sum(){
	var i = document.querySelector("#num");
	var price = document.querySelector(".sale-price");
	document.querySelector(".totalcost").innerText = i * price;
}*/
   // 탭 변경 부분 - 완
	$('.contentNav li').click(function(e){
		e.preventDefault();
 		var idx = $(this).index();
 		$('.contentNav li').removeClass('active').eq(idx).addClass('active');
 		$('table').removeClass('active').eq(idx).addClass('active');
 		});

   // 상품 후기 부분 - 임시 완
   $('.tproduct-review tbody tr .tcontent').click(function(){
   //전체 글자의 변수를 2번 잡아서 . 한번은 위쪽 내용. 한번은 아래쪽 내용 출력
   //위쪽 내용
    var text = $(this).children('span').html(); //전체 html또는 text를 가져와서
    var full = $(this).closest('tr').next('tr').children('td').eq(1).text(text).css('text-align','left'); // tr 출력후 나머지 글자 출력 및 정렬
    // var cut = $(this).closest('tr').next('tr').children('td').eq(1).text();
   $(this).closest('tr').next('tr').toggleClass('display'); //자세한 이용후기 tr 출력하기
  });



function Click1() {
	alert("구매하기");
}

function Click2() {
	alert("찜하기");
}

function Click3() {
	alert("장바구니");
}
</script>
 <script>
  function changeImage(img) {
    document.getElementById("main-image").src = img.querySelector('img').src;
  }

  function hoverImage(img) {
    var mainImage = document.getElementById("main-image");
    mainImage.src = img.querySelector('img').src;
  }
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
		<%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>

		<section>
			<div class="main">
				<div class="container">

			
				
<%-- 본문시작 --%>
	<div class="shCMSshop">
		<div class="shopView">
			<div class="viewHeader">
				<!-- 상품이미지 -->
				<%--<form action="location='" method="get"> --%>
				<div class="productImg">
					<div class="mainImg">
		<div id="main-image-container">
  <img id="main-image" src="/upload${detail.product_cont1}" width="500" height="500" alt="음식 이미지1">
</div>

<div class="thumbnail-container">
  <c:if test="${!empty detail.product_cont1}">
    <div class="thumbnail" onclick="changeImage(this);" onmouseover="hoverImage(this);">
      <img src="/upload${detail.product_cont1}" width="125" height="100" alt="음식 이미지1">
    </div>
  </c:if>
  <c:if test="${!empty detail.product_cont2}">
    <div class="thumbnail" onclick="changeImage(this);" onmouseover="hoverImage(this);">
      <img src="/upload${detail.product_cont2}" width="125" height="100" alt="음식 이미지2">
    </div>
  </c:if>
  <c:if test="${!empty detail.product_cont3}">
    <div class="thumbnail" onclick="changeImage(this);" onmouseover="hoverImage(this);">
      <img src="/upload${detail.product_cont3}" width="125" height="100" alt="음식 이미지3">
    </div>
  </c:if>
  <c:if test="${!empty detail.product_cont4}">
    <div class="thumbnail" onclick="changeImage(this);" onmouseover="hoverImage(this);">
      <img src="/upload${detail.product_cont4}" width="125" height="100" alt="음식 이미지4">
    </div>
  </c:if>
</div>
					
					
					
					</div>
					<%-- 
					<ul>
						<li class="subImg"><img src="https://search.pstatic.net/common/?src=http%3A%2F%2Fshop1.phinf.naver.net%2F20210730_134%2F1627627649541acadd_PNG%2F28763538245462198_1164728166.png&type=sc960_832" width="85" height="85" 
    cursor="pointer"
    margin-left="30px"
						alt="서브 이미지1"></li>
						<li><img src="https://search.pstatic.net/common/?src=http%3A%2F%2Fshop1.phinf.naver.net%2F20210730_134%2F1627627649541acadd_PNG%2F28763538245462198_1164728166.png&type=sc960_832" width="85" height="85" 
    cursor="pointer"
    margin-left="30px" alt="서브 이미지2"></li>
						<li><img src="sub01.jpg" alt="서브 이미지3"></li>
						<li><img src="sub01.jpg" alt="서브 이미지4"></li>
					</ul>
					--%>
				</div>
				<!-- 상품 설명 -->
				<div class="productInfo">
					<h1 id="name">${detail.product_title}</h1>
					<div class="price">
  <span class="sale-price" style="margin-left: 10px;" id="cost">
    <fmt:formatNumber type="number" value="${detail.product_price}" pattern="#,###원" />
  </span>
</div>
					
					
					<div class="star-ratings">평점       	<span >${detail.product_score}</span></div>
					<div class="manufact">제조사       <span>${detail.product_maker}</span></div>
					<div class="categori">분류           <span>${detail.product_type}</span></div>
					<div class="item">
						<span class="it">
							<%--<a href="" class="minur" style="border: none; background: white;" onclick="minus()">-</a>--%>
							<input type="button" value="-" onclick="minus()" style="background: white; border: none;">
							<span id="num">1</span>
							<input type="button" value="+" onclick="plus()" style="background: white; border: none;">
							<%-- <a href="" class="plus" style="border: none; background: white;" onclick="plus()">+</a>--%>
						</span>
					</div>
					<div class="all-price">총 상품금액        <span id="price" class="totalcost"><fmt:formatNumber type="number" value="${detail.product_price}" pattern="#,###" /></span>원</div>
					
					

					<div class="btn">
						<div class="first" id="buy">
							<%--<a href="#" class="psbtn"  onclick="sendPost('payment.shop?product_title=${p.product_title}&product_price=${p.product_price}');">구매하기</a> --%>
							<input type="button"  data-tab="4" id="gume" class="psbtn" value="구매하기" >
						</div>
						
						<div class="second" id="like_cart">
						
							<a data-tab="1" class="like" >찜 하기</a>
							
							
							
							<a data-tab="3" class="cart">장바구니</a>
							
						</div>
					</div>
			
			</div>
			<%--</form> --%>
			
			
<div class="viewBody">
  <div class="container">
    <ul class="contentNav">
      <li class="on"><a>상품정보</a></li>
      <li><a>리뷰</a></li>
      <li><a>Q&A</a></li>
    </ul>
    
    <div class="tab_cont">
      <div class="on">
        <div id="tab1Content" class="tab-content">
          <!-- 상품 정보 내용 -->
          <h2>상품 정보</h2>
          <ul>
            <li><h2></h2></li>
            <c:if test="${!empty detail.product_cont5}">
              <li><img src="/upload${detail.product_cont5}" style="height: auto; width: 800px;"></li>
            </c:if>
            <c:if test="${!empty detail.product_cont6}">
              <li><img src="/upload${detail.product_cont6}" style="height: auto; width: 800px;"></li>
            </c:if>
            <c:if test="${!empty detail.product_cont7}">
              <li><img src="/upload${detail.product_cont7}" style="height: auto; width: 800px;"></li>
            </c:if>
            <c:if test="${!empty detail.product_cont8}">
              <li><img src="/upload${detail.product_cont8}" style="height: auto; width: 800px;"></li>
            </c:if>
          </ul>
        </div>
      </div>
      <div>
        tab2_content
      </div>
      <div>
      
        <!-- 수정된 내용 시작 -->
        <div id="tab3Content" class="tab-content">
          <h2>Q&A</h2>
          <input type ="button" value="상품문의하기" class="qna" data-tab="1">
          <table>
  <tr>
    <th width="5%" height="26">아이디</th>
    <th width="35%">질문제목</th>
    <th width="40%">질문내용</th>
    <th width="10%">문의날짜</th>
    <th width="10%">답변상태</th>
    
  </tr>
  <c:forEach var="a" items="${detail2}">
    <tr>
      <td>${a.qna_mem_id}</td>
      <td>${a.qna_title}</td>
      <td>${a.qna_content}</td>
      <td>${a.qna_date.substring(0,10)}</td>
      <c:if test="${a.qna_reply != ' '}">
        <th width="14%"><a href="javascript:void(0);" onclick="toggleReply(this);">답변완료</a></th>
      </c:if>
      <c:if test="${a.qna_reply == ' '}">
        <th width="14%">답변대기</th>
      </c:if>
    </tr>
    <tr class="hidden">
     
           <td>>>></td>
            <td colspan="2">${a.qna_reply}</td>
          
        
    </tr>
  </c:forEach>
</table>
        </div>
        <!-- 수정된 내용 끝 -->
      </div>
    </div>
  </div>
</div>
		</section>
	
	<%-- top버튼 삭제 X --%>
	<div id="topBtn">
		<span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
	</div>
	
	<%-- 푸터 영역 --%>
	<footer>
		<jsp:include page="../include/footer.jsp"/>
	</footer>
	</div>
	
	<script>
  function toggleReply(element) {
    var replyRow = element.parentNode.parentNode.nextElementSibling;
    replyRow.classList.toggle("hidden");
  }
</script>
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
	<script>
  $(document).ready(function() {
    $(".contentNav li").click(function() {
      var idx = $(this).index();
      $(".contentNav li").removeClass("on");
      $(".contentNav li").eq(idx).addClass("on");
      $(".tab_cont > div").hide();
      $(".tab_cont > div").eq(idx).show();

      // 추가된 코드 시작
      $(".tab_cont > div").eq(idx).find("table").show();
      // 추가된 코드 끝
    });

    // 초기에는 tab1_content만 보여줍니다.
    $(".tab_cont > div").hide();
    $(".tab_cont > div").eq(0).show();
    $(".tab_cont > div").eq(0).find("table").show(); // 초기에는 첫 번째 탭의 테이블 내용을 보여줍니다.
  });
</script>

<script src="../../js/qna.js"></script>
<script src="../../js/like_cart.js"></script>
</body>
</html>