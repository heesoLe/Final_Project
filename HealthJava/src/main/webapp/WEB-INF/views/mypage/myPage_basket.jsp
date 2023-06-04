<%@ page contentType="text/html; charset=UTF-8" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<script src="https://code.jquery.com/jquery-3.6.3.js"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>

<title>HealthJava 장바구니</title>

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
	
	.price, .quantity, .subtotal {
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
		width: 75%;
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
</style>

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
							<li><a href="myPage_orderCancel" class="liList">주문ㆍ배송</a></li>
							<li><a href="myPage_like" class="liList">찜 목록</a></li>
							<li><a href="myPage_basket" class="liList" style="color: #B21948;">장바구니</a></li>
							<li style="margin-bottom: 30px;"><a href="myPage_inquiry" class="liList">문의 내역</a></li>
	
							<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 회원 정보</li>
							<li><a href="myPage_updateInfo" class="liList">회원정보 변경</a></li>
							<li><a href="myPage_changePwd" class="liList">비밀번호 변경</a></li>
							<li><a href="myPage_user_Withdrawal" class="liList">회원탈퇴</a></li>
							<li style="margin-bottom: 30px;"><a href="myPage_updateAddress" class="liList">배송지 관리</a></li>
							
							<li style="font-weight: bold; font-size: 20px; border-bottom-width: 3px; border-bottom-style: solid; border-bottom-color: black;"> 나의 상품후기</li>
							<li><a href="myPage_review" class="liList">나의 상품후기</a></li>
						</ul>
					</nav>
				</aside>
				
				<%-- 장바구니 --%>
			<div class="wishBox">
				<div class="listTitleBox">
					<span id="listTitle">장바구니</span>
				</div>
				<div class="basketcontentBox">
					<div class="basket">
						<div class="basket-labels">
							<ul>
								<li class="item item-heading">상품명</li>
								<li class="price">판매가</li>
								<li class="quantity">수량</li>
								<li class="subtotal">합계 금액</li>
							</ul>
						</div>
						<div class="basket-product">
							<div class="item">
								<div class="product-image">
									<img src="https://img-cf.kurly.com/cdn-cgi/image/width=676,format=auto/shop/data/goods/1637924624422l0.jpeg" alt="상품 이미지" class="product-frame">
								</div>
								<div class="product-details">
									<span id="productTitle"><strong>청송 사과 1.5kg(5~7입)</strong></span>
								</div>
							</div>
							<div class="price">8,900원</div>
							<div class="quantity">
								<input type="number" value="1" min="1" class="quantity-field">
							</div>
							<div class="subtotal" id="sum">8,900원</div>
							<div class="remove">
								<button>삭제하기</button>
							</div>
						</div>
							
					<!-- 결제 창 -->
					<aside class="aside_right">
						<div class="summary">
							<div class="summary-total-items">
								<span class="total-items"></span>개의 상품이 담겼습니다.
							</div>
							<div class="summary-subtotal">
								<div class="total-title">배송 형태<br>배송비
								</div>
								<div class="subtotal-value">택배배송<br>배송비<strong>무료</strong>
								</div>
								<div class="summary-promo hide">
									<div class="promo-title">Promotion</div>
									<div class="promo-value final-value" id="basket-promo"></div>
								</div>
							</div>
							<div class="summary-delivery"></div>
							<div class="summary-total">
								<div class="total-title">합계 금액</div>
								<div class="total-value final-value" id="basket-total">
									<span class="total-price"></span>원
								</div>
							</div>
							<div class="summary-checkout">
								<button class="checkout-cta">구매하기</button>
							</div>
						</div>
					</aside>
				
				<%-- 페이징 처리 --%>
				<div id="pagination">
					<!-- 검색 칸 공백 시 페이징 사라지지 않게 -->
	               <c:if test="${find_name == ''}"> <%--검색필드와 검색어가 없는 경우 --%>
	                 <c:if test="${page <= 1}">
	                  PREV&nbsp;
	                 </c:if>
	                 <c:if test="${page>1}">
	                  <a href="myPage_like?page=${page-1}">PREV</a>&nbsp;
	                 </c:if>
	                 
	                 <%--현재 쪽번호 출력 --%>
	                 <c:forEach var="a" begin="${startpage}" end="${endpage}" step="1">
	                   <c:if test="${a == page}"> <%-- 현재 페이지가 선택된 경우 --%>
	                      [&nbsp;${a}&nbsp;]
	                   </c:if>
	                   <c:if test="${a != page}"> <%--현재 쪽번호가 선택 안 된 경우--%>
	                    <a href="myPage_like?page=${a}">[&nbsp;${a}&nbsp;]</a>&nbsp;
	                   </c:if>
	                 </c:forEach>
	                   
	                
	                <c:if test="${page >= maxpage}">
	                  &nbsp;NEXT
	                </c:if>
	                <c:if test="${page < maxpage}">
	                 <a href="myPage_like?page=${page+1}">NEXT</a>
	                </c:if>
	               </c:if>
	               
	               <!-- 검색 칸 공백 시 페이징 사라지지 않게 -->
				    <%--검색 전 페이징 --%>
				    <c:if test="${(empty find_field) && (empty find_name)}"> <%--검색필드와 검색어가 없는 경우 --%>
				     <c:if test="${page <= 1}">
				      PREV&nbsp;
				     </c:if>
				     <c:if test="${page>1}">
				      <a href="myPage_like?page=${page-1}">PREV</a>&nbsp;
				     </c:if>
				     
				     <%--현재 쪽번호 출력 --%>
				     <c:forEach var="a" begin="${startpage}" end="${endpage}" step="1">
				       <c:if test="${a == page}"> <%-- 현재 페이지가 선택된 경우 --%>
				       	[&nbsp;${a}&nbsp;]
				       </c:if>
				       <c:if test="${a != page}"> <%--현재 쪽번호가 선택 안 된 경우--%>
				        <a href="myPage_like?page=${a}">[&nbsp;${a}&nbsp;]</a>&nbsp;
				       </c:if>
				     </c:forEach>
				       
				    
				    <c:if test="${page >= maxpage}">
				      &nbsp;NEXT
				    </c:if>
				    <c:if test="${page < maxpage}">
				     <a href="myPage_like?page=${page+1}">NEXT</a>
				    </c:if>
				   </c:if>
				    
				    <%-- <%--검색이후 페이징(쪽나누기) --%>
				    <c:if test="${(!empty find_field) && (!empty find_name)}"> 검색필드와 검색어가 있는 경우
				     <c:if test="${page <= 1}">
				      PREV&nbsp;
				     </c:if>
				     <c:if test="${page>1}">
				      <a href="myPage_like?page=${page-1}&find_field=${find_field}&find_name=${find_name}">PREV</a>&nbsp;
				      &(엠퍼센트) 구분기호로 구분하면서 find_field=검색필드&find_name= 검색어를 get방식으로 전달해야 검색 이후 페이징 목록을 유지한다.그렇지 않으면 검색전 전체 페이징 목록으로 이동해서 검색 효과가 사라진다.
				     </c:if> --%>
				     
				     <%--현재 쪽번호 출력 --%>
				     <c:forEach var="a" begin="${startpage}" end="${endpage}" step="1">
				       <c:if test="${a == page}"> <%-- 현재 페이지가 선택된 경우 --%>
				        [&nbsp;${a}&nbsp;]
				       </c:if>
				       <c:if test="${a != page}"> <%--현재 쪽번호가 선택 안 된 경우--%>
				        <a href="myPage_like?page=${a}&find_field=${find_field}&find_name=${find_name}">[&nbsp;${a}&nbsp;]</a>&nbsp;
				       </c:if>
				     </c:forEach>      
				    
				    <c:if test="${page >= maxpage}">
				      &nbsp;NEXT
				    </c:if>
				    <c:if test="${page < maxpage}">
				     <a href="myPage_like?page=${page+1}&find_field=${find_field}&find_name=${find_name}">NEXT</a>
				    </c:if>
				   </c:if> 
				   </div> <%-- end 페이징처리 --%>
				</div>
				</div>			
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
		
		<%-- 장바구니 부분 --%>
		/* 장바구니 분 */
		var promoCode;
		var promoPrice;
		var fadeTime = 300;

		$('.quantity input').change(function() {
		  updateQuantity(this);
		});

		$('.remove button').click(function() {
		  removeItem(this);
		});

		$(document).ready(function() {
		  updateSumItems();
		});

		$(document).ready(function() {
		  readyPrice();
		});

		/* $('.promo-code-cta').click(function() {
		  promoCode = $('#promo-code').val();
		  if (promoCode == '10off' || promoCode == '10OFF') {
		    //promoPrice에 값이 없으면 10OFF 프로모션 코드에 대해 10으로 설정합니다.
		    if (!promoPrice) {
		      promoPrice = 10;
		    } else if (promoCode) {
		      promoPrice = promoPrice * 1;
		    }
		  } else if (promoCode != '') {
		    alert("Invalid Promo Code");
		    promoPrice = 0;
		  }
		  //설정된 promoPrice가 있는 경우 프로모션 표시(유효한 promoCode 입력이 있음을 의미)
		  if (promoPrice) {
		    $('.summary-promo').removeClass('hide');
		    $('.promo-value').text(new Intl.NumberFormat("ko-KR", { currency: "KRW", currencyDisplay: "symbol" }).format(promoPrice));
		    recalculateCart(true);
		  }
		}); */

		/* 합계  */
		function recalculateCart(onlyTotal) {
		  var subtotal = 0;

		  /* Sum up row totals */
		  $('.basket-product').each(function() {
		    subtotal += parseFloat($(this).children('.subtotal').text().replace("원", "").replace(",", ""));
		  });

		  /* Calculate totals */
		  var total = subtotal;

		  //If there is a valid promoCode, and subtotal < 10 subtract from total
		  var promoPrice = parseFloat($('.promo-value').text().replace("원", "").replace(",", ""));
		  if (promoPrice) {
		    if (subtotal >= 10) {
		      total -= promoPrice;
		    } else {
		      alert('Order must be more than ₩10 for Promo code to apply.');
		      $('.summary-promo').addClass('hide');
		    }
		  }

		  /*If switch for update only total, update only total display*/
		  if (onlyTotal) {
		    /* Update total display */
		    $('.total-value').fadeOut(fadeTime, function() {
		      $('#basket-total').html(new Intl.NumberFormat("ko-KR", { currency: "KRW", currencyDisplay: "symbol" }).format(total)+"원");
		      $('.total-value').fadeIn(fadeTime);
		    });
		  } else {
		    /* Update summary display. */
		    $('.final-value').fadeOut(fadeTime, function() {
		      $('#basket-subtotal').html(new Intl.NumberFormat("ko-KR", { currency: "KRW", currencyDisplay: "symbol" }).format(subtotal)+"원");
		      $('#basket-total').html(new Intl.NumberFormat("ko-KR", { currency: "KRW", currencyDisplay: "symbol" }).format(total)+"원");
		      if (total == 0) {
		        $('.checkout-cta').fadeOut(fadeTime);
		      } else {
		        $('.checkout-cta').fadeIn(fadeTime);
		      }
		      $('.final-value').fadeIn(fadeTime);
		    });
		  }
		}

		/* Update quantity */
		function updateQuantity(quantityInput) {
		  /* Calculate line price */
		  var productRow = $(quantityInput).parent().parent();
		  var price = parseFloat(productRow.children('.price').text().replace("원", "").replace(",", ""));
		  var quantity = $(quantityInput).val();
		  var linePrice = price * quantity;

		  /* Update line price display and recalc cart totals */
		  productRow.children('.subtotal').each(function() {
		    $(this).fadeOut(fadeTime, function() {
		      $(this).text(new Intl.NumberFormat("ko-KR", { currency: "KRW", currencyDisplay: "symbol" }).format(linePrice) + "원");
		      recalculateCart();
		      $(this).fadeIn(fadeTime);
		    });
		  });

		  productRow.find('.item-quantity').text(quantity);
		  updateSumItems();
		}

		function updateSumItems() {
		  var sumItems = 0;
		  $('.quantity input').each(function() {
		    sumItems += parseInt($(this).val());
		  });
		  $('.total-items').text(sumItems);
		}

		function readyPrice() {
		  var content_div = document.getElementById("sum");

		  var sumPrice = 0;
		  $(content_div.innerText).each(function() {
		    sumPrice += parseInt($(content_div.innerText).val())+"원";
		  });
		  $('.total-price').text(new Intl.NumberFormat("ko-KR", { currency: "KRW", currencyDisplay: "symbol" }).format(sumPrice));
		}

		/* 장바구니 삭제 */
		function removeItem(removeButton) {
		  /* Remove row from DOM and recalc cart total */
		  var productRow = $(removeButton).parent().parent();
		  productRow.slideUp(fadeTime, function() {
		    productRow.remove();
		    recalculateCart();
		    updateSumItems();
		  });
		}
	</script>
</body>
</html>