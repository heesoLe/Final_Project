<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<jsp:include page="../include/header.jsp"/>

<script type="text/javascript" src="<%=request.getContextPath()%>/js/jquery.js"></script>
<script	src="../js/cs.js"></script>

<style>

.main{
 min-height: 730px;
}

#cs_faq_list {
	list-style: none;
	position: relative;
	padding: 0px 0px 0px 10%;
	font-family: 'KIMM_Bold';
	color: #b21949;
}

#cs_faq_list li {
	display: inline;
	padding: 10px 10px;
}

#cs_faq_list li a {
	color: inherit;
	text-decoration: none;
	font-size: 25px;
	font-family: 'KIMM_Bold';
}

#label {
	list-style: none;
	position: relative;
	padding: 0px 0px 0px 10%;
	font-family: 'KIMM_Bold';
}

#inquire_notice_list {
	display: inline;
}

#label li {
	display: inline;
	padding: 10px 10px;
	color: gray;
	font-size: 15px;
}

#cs_faq_list li a:hover {
	text-decoration: none;
	color: black;
	cursor: pointer;
}

table {
	border-collapse: collapse;
	border-spacing: 0;
}

div .select {
	padding: 80px 0;
}

section.notice {
	padding: 120px 0px 20px 0px;
}

/* .page-title {
  margin-bottom: 60px;
}
.page-title h3 {
  font-size: 28px;
  color: #333333;
  font-weight: 400;
  text-align: center;
} */

/*  
.board-table tbody .hidden {
  선택된 행에 스타일 적용
  display: none;
}
 */
#board-search {
	margin: auto;
}

#board-search .search-window {
	padding: 15px 0;
	background-color: #f9f7f9;
}

#board-search .search-window .search-wrap {
	position: relative;
	/*   padding-right: 124px; */
	margin: 0 auto;
	width: 80%;
	max-width: 564px;
}

#board-search .search-window .search-wrap input {
	height: 40px;
	width: 100%;
	font-size: 14px;
	padding: 7px 14px;
	border: 1px solid #ccc;
	font-family: 'KIMM_Bold';
}

#board-search .search-window .search-wrap input:focus {
	border-color: #333;
	outline: 0;
	border-width: 1px;
}

#board-search .search-window .search-wrap .btn {
	position: absolute;
	right: 0;
	top: 0;
	bottom: 0;
	width: 108px;
	padding: 0;
	font-size: 16px;
	font-family: 'KIMM_Bold';
	color: white;
	background: #b21949;
}

.board-table {
	font-size: 13px;
	width: 100%;
	border-top: 1px solid #ccc;
	border-bottom: 1px solid #ccc;
	font-family: 'KIMM_Bold';
}

.board-table a {
	color: #333;
	display: inline-block;
	line-height: 1.4;
	word-break: break-all;
	vertical-align: middle;
	text-decoration: none;
}

.board-table a:hover {
	text-decoration: underline;
}

.board-table th {
	text-align: center;
}

.board-table .th-num {
	width: 100px;
	text-align: center;
	font-size: 15px;
	background-color: #b21949;
}

.board-table .th-title {
	background-color: #b21949;
	font-size: 15px;
}

.board-table .th-date {
	background-color: #b21949;
	width: 200px;
	font-size: 15px;
}

.board-table .th-name {
	background-color: #b21949;
	width: 200px;
	font-size: 15px;
}

.board-table th, .board-table td {
	padding: 14px 0;
}

.board-table tbody td {
	border-top: 1px solid #e7e7e7;
	text-align: center;
	font-size: larger;
    color: #b21949;
}

.board-table tbody th {
	padding-left: 28px;
	padding-right: 14px;
	border-top: 1px solid #e7e7e7;
	text-align: center;
}

.board-table tbody th p {
	display: none;
}

.board-table tbody tr.hidden {
	display: none;
}

.board-table tbody tr:nth-child(even) {
	background-color: #b21949;
}

.btn {
	display: inline-block;
	padding: 0 30px;
	font-size: 15px;
	font-weight: 400;
	background: transparent;
	text-align: center;
	white-space: nowrap;
	vertical-align: middle;
	-ms-touch-action: manipulation;
	touch-action: manipulation;
	cursor: pointer;
	-webkit-user-select: none;
	-moz-user-select: none;
	-ms-user-select: none;
	user-select: none;
	border: 1px solid transparent;
	text-transform: uppercase;
	-webkit-border-radius: 0;
	-moz-border-radius: 0;
	border-radius: 0;
	-webkit-transition: all 0.3s;
	-moz-transition: all 0.3s;
	-ms-transition: all 0.3s;
	-o-transition: all 0.3s;
	transition: all 0.3s;
}

.btn-dark {
	background: #555;
	color: #fff;
}

.btn-dark:hover, .btn-dark:focus {
	background: #373737;
	border-color: #373737;
	color: #fff;
}

.btn-dark {
	background: #555;
	color: #fff;
}

.btn-dark:hover, .btn-dark:focus {
	background: #373737;
	border-color: #373737;
	color: #fff;
}

.btn_contact {
	height: 80px;
	width: 100%;
	margin: auto;
	
	padding: 30px 0px 20px 0px;
	display: inline-block;
	font-size: 15px;
	font-weight: 400;
	background: transparent;
	text-align: center;
	white-space: nowrap;
}

.btn_1 {
	height: 40px;
	width: 100px;
	background: #FC5400;
	color: #fff;
	font-family: 'KIMM_Bold';
}

.btn_1:hover, .btn_1:focus {
	background: #b21949;
	border-color: #b21949;
	color: #fff;
}

.btn_1 {
	background: #b21949;
	color: #fff;
}

.btn_1:hover, .btn_1:focus {
	background: #b21949;
	border-color: #b21949;
	color: #fff;
}

/* reset */
* {
	list-style: none;
	text-decoration: none;
	padding: 0;
	margin: 0;
	box-sizing: border-box;
}

.clearfix:after {
	content: '';
	display: block;
	clear: both;
}

.container {
	width: 1100px;
	margin: 0 auto;
}

.blind {
	position: absolute;
	overflow: hidden;
	clip: rect(0, 0, 0, 0);
	margin: -1px;
	width: 1px;
	height: 1px;
}

#label_hr {
	border: 0;
	height: 4px; /* hr 높이 설정 */
	background-color: #b21949; /* hr 색상 설정 */
	margin: 10px 0px; /* hr 위아래 간격 설정 */
}

p {
	font-size: medium;
	background-color: white;
}

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
      color: #b21949; /* 글자색상 */
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
      background-color: #b21949;
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
      border-bottom: 1px solid #b21949;
   }
   
   .pl{
   border: 1px solid #9B51E0;
   border-radius: 3px;
    height: 35px; 
}

.pl:focus{
    border: 1px solid #9B51E0;
    box-sizing: border-box;
    border-radius: 10px;
    outline: 3px solid #F8E4FF;
    border-radius: 3px;
}
</style>
<div class="main">
<section class="notice">

<div style="margin-top: 10px;">
 <ul id="cs_faq_list">
  <li><a href="notice">공지사항</a></li>
  <li><a href="FAQ">자주 묻는 질문</a></li>
  <li><a href="contact">1:1문의</a></li>
 </ul>
 <hr id="label_hr">
</div>
    <!-- board seach area -->
    <div id="board-search">
        <div class="container">
            <div class="search-window">
                <form action="notice" method="post">
                    <div class="search-wrap">
                        <label for="search" class="blind">공지사항 내용 검색</label>
                        <!-- <input id="search" type="search" name="" placeholder="검색어를 입력해주세요." value="">
                        <button type="submit" class="btn btn-dark">검색</button> -->
                        <select name="search_type" id="search_type" class="pl">
								<option value="notice_title" 
								<c:if test="${search_type == 'notice_title' }">${'selected' }</c:if>>제목</option>
								<option value="notice_cont" 
								<c:if test="${search_type == 'notice_cont' }">${'selected' }</c:if>>내용</option>
							</select>
							<input type="search" name="search_field" id="search_field" placeholder="검색어를 입력해주세요." value="${search_field }"
							 style="width:500px;" />
							<input id="btn" name="search" class="btn btn-dark" type="submit" value="검색" />
                    </div>
                </form>
            </div>
        </div>
    </div>
   
  <!-- board list area -->
    <div id="board-list">
        <div class="container">
            <table class="board-table">
                <thead>
                <tr>
                    <th scope="col" class="th-num" style="color:white;">번호</th>
                    <th scope="col" class="th-title" style="color:white;">제목</th>
                  	<th scope="col" class="th-date" style="color:white;">등록일</th> 
                </tr>
                 <tr></tr>
                </thead>
                <tbody>
                <c:if test="${!empty nlist }"> <%-- 검색 전후 목록이 있는 경우 실행 --%>
				<c:forEach var="c" items="${nlist }">
				<tr onclick="toggleContent(this)">
                    <td >${c.notice_no }</td>
                    <th><a href="#">${c.notice_title }</a></th>
                    <td>${c.notice_date.substring(0,10)}</td>
               	</tr>
                <tr class="hidden">
                	<td style="background-color:#f1f1f1; color:#b21949;"></td>
                	<td style="background-color:#f1f1f1; color:#b21949;">${c.notice_cont}</td>
                	<td style="background-color:#f1f1f1; color:#b21949;"></td>
                </tr>
				</c:forEach>	
						</c:if > 
						
						<%-- 작성글이 있을경우 --%>
						<c:if test="${empty nlist }">
						<tr>
						<td colspan="5">작성 글이 없습니다.</td>
						</tr>
						</c:if>
                
                </tbody>
            </table>
        </div>
    </div>
    				<%-- top버튼 삭제 X --%>
				<div id="topBtn">
					<span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
				</div>
    </section>
<%-- 페이징 처리 --%>
					<div id="pagination" align="center">
				    <%--검색 전 페이징 --%>
				    <c:if test="${(empty search_type) && (empty search_field)}"> <%--검색필드와 검색어가 없는 경우 --%>
				     <c:if test="${page <= 1}">
				      PREV&nbsp;
				     </c:if>
				     <c:if test="${page>1}">
				      <a href="notice?page=${page-1}">PREV</a>&nbsp;
				     </c:if>
				     
				     <%--현재 쪽번호 출력 --%>
				     <c:forEach var="a" begin="${startpage}" end="${endpage}" step="1">
				       <c:if test="${a == page}"> <%-- 현재 페이지가 선택된 경우 --%>
				       	[&nbsp;${a}&nbsp;]
				       </c:if>
				       <c:if test="${a != page}"> <%--현재 쪽번호가 선택 안 된 경우--%>
				        <a href="notice?page=${a}">[&nbsp;${a}&nbsp;]</a>&nbsp;
				       </c:if>
				     </c:forEach>
				       
				    
				    <c:if test="${page >= maxpage}">
				      &nbsp;NEXT
				    </c:if>
				    <c:if test="${page < maxpage}">
				     <a href="notice?page=${page+1}">NEXT</a>
				    </c:if>
				   </c:if>
				   
				   <!--  -->
				   <c:if test="${search_field == ''}"> <%--검색필드와 검색어가 없는 경우 --%>
				     <c:if test="${page <= 1}">
				      PREV&nbsp;
				     </c:if>
				     <c:if test="${page>1}">
				      <a href="notice?page=${page-1}">PREV</a>&nbsp;
				     </c:if>
				     
				     <%--현재 쪽번호 출력 --%>
				     <c:forEach var="a" begin="${startpage}" end="${endpage}" step="1">
				       <c:if test="${a == page}"> <%-- 현재 페이지가 선택된 경우 --%>
				       	[&nbsp;${a}&nbsp;]
				       </c:if>
				       <c:if test="${a != page}"> <%--현재 쪽번호가 선택 안 된 경우--%>
				        <a href="notice?page=${a}">[&nbsp;${a}&nbsp;]</a>&nbsp;
				       </c:if>
				     </c:forEach>
				       
				    
				    <c:if test="${page >= maxpage}">
				      &nbsp;NEXT
				    </c:if>
				    <c:if test="${page < maxpage}">
				     <a href="notice?page=${page+1}">NEXT</a>
				    </c:if>
				   </c:if>
				   <!--  -->
				    
				    <%--검색이후 페이징(쪽나누기) --%>
				    <c:if test="${(!empty search_type) && (!empty search_field)}"> <%--검색필드와 검색어가 있는 경우 --%>
				     <c:if test="${page <= 1}">
				      PREV&nbsp;
				     </c:if>
				     <c:if test="${page>1}">
				      <a href="notice?page=${page-1}&search_type=${search_type}&find_name=${search_field}">PREV</a>&nbsp;
				      <%-- &(엠퍼센트) 구분기호로 구분하면서 find_field=검색필드&find_name= 검색어를 get방식으로 전달해야 검색 이후 페이징 목록을 유지한다.그렇지 않으면 검색전 전체 페이징 목록으로 이동해서 검색 효과가 사라진다. --%>
				     </c:if>
				     
				     <%--현재 쪽번호 출력 --%>
				     <c:forEach var="a" begin="${startpage}" end="${endpage}" step="1">
				       <c:if test="${a == page}"> <%-- 현재 페이지가 선택된 경우 --%>
				        [&nbsp;${a}&nbsp;]
				       </c:if>
				       <c:if test="${a != page}"> <%--현재 쪽번호가 선택 안 된 경우--%>
				        <a href="notice?page=${a}&search_type=${search_type}&search_field=${search_field}">[&nbsp;${a}&nbsp;]</a>&nbsp;
				       </c:if>
				     </c:forEach>      
				    
				    <c:if test="${page >= maxpage}">
				      &nbsp;NEXT
				    </c:if>
				    <c:if test="${page < maxpage}">
				     <a href="notice?page=${page+1}&search_type=${search_type}&search_field=${search_field}">NEXT</a>
				    </c:if>
				   </c:if> 
				   </div>
<c:if test="${session_id=='admin' }">
 <div class="btn_contact" >
 <form action="">
   <button type="button" class="btn_1" onclick="location='/notice_write';">공지사항 추가</button>
 </form>
</div>
</c:if>
	</div>
	
	<%-- 푸터 영역 --%>
	<footer>
	<!-- footer -->
	<jsp:include page="../include/footer.jsp"/>
	
	</footer>
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
		/* Set values + misc */
		var promoCode;
		var promoPrice;
		var fadeTime = 300;

		/* Assign actions */
		$('.quantity input').change(function() {
			updateQuantity(this);
		});

		$('.remove button').click(function() {
			removeItem(this);
		});

		$(document).ready(function() {
			updateSumItems();
		});

		$('.promo-code-cta').click(function() {

			promoCode = $('#promo-code').val();

			if (promoCode == '10off' || promoCode == '10OFF') {
				//If promoPrice has no value, set it as 10 for the 10OFF promocode
				if (!promoPrice) {
					promoPrice = 10;
				} else if (promoCode) {
					promoPrice = promoPrice * 1;
				}
			} else if (promoCode != '') {
				alert("Invalid Promo Code");
				promoPrice = 0;
			}
			//If there is a promoPrice that has been set (it means there is a valid promoCode input) show promo
			if (promoPrice) {
				$('.summary-promo').removeClass('hide');
				$('.promo-value').text(promoPrice.toFixed(0) + "원");
				recalculateCart(true);
			}
		});
		
		
		/* Recalculate cart */
		function recalculateCart(onlyTotal) {
			var subtotal = 0;

			/* Sum up row totals */
			$('.basket-product').each(function() {
				subtotal += parseFloat($(this).children('.subtotal').text());
			});

			/* Calculate totals */
			var total = subtotal;

			//If there is a valid promoCode, and subtotal < 10 subtract from total
			var promoPrice = parseFloat($('.promo-value').text());
			if (promoPrice) {
				if (subtotal >= 10) {
					total -= promoPrice;
				} else {
					alert('Order must be more than £10 for Promo code to apply.');
					$('.summary-promo').addClass('hide');
				}
			}

			/*If switch for update only total, update only total display*/
			if (onlyTotal) {
				/* Update total display */
				$('.total-value').fadeOut(fadeTime, function() {
					$('#basket-total').html(total.toFixed(0) + "원");
					$('.total-value').fadeIn(fadeTime);
				});
			} else {
				/* Update summary display. */
				$('.final-value').fadeOut(fadeTime, function() {
					$('#basket-subtotal').html(subtotal.toFixed(0) + "원");
					$('#basket-total').html(total.toFixed(0) + "원");
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
			var price = parseFloat(productRow.children('.price').text());
			var quantity = $(quantityInput).val();
			var linePrice = price * quantity;

			/* Update line price display and recalc cart totals */
			productRow.children('.subtotal').each(function() {
				$(this).fadeOut(fadeTime, function() {
					$(this).text(linePrice.toFixed(0) + "원");
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

		/* Remove item from cart */
		function removeItem(removeButton) {
			/* Remove row from DOM and recalc cart total */
			var productRow = $(removeButton).parent().parent();
			productRow.slideUp(fadeTime, function() {
				productRow.remove();
				recalculateCart();
				updateSumItems();
			});
		}
		
		<%-- 리뷰 작성 페이지 부분 --%>
		// 왼쪽 사이드바의 '나의 후기' 텍스트 클릭시 새창 열기
		function openPopup_review_write() {
	        var page_width = '490';
	        var page_height = '900';
	    
	        // 팝업을 가운데 위치시키기 위해 아래와 같이 값 구하기
	        var page_left = Math.ceil((window.screen.width - page_width)/2);
	        var page_top = Math.ceil((window.screen.height - page_height)/2);
	
	    window.open("http://localhost:8046/MVC/page/mypage2/review_write.jsp", "review_write",'width='+ page_width +', height='+ page_height +', left=' + page_left + ', top='+ page_top);
	    
	    }
		
	</script>