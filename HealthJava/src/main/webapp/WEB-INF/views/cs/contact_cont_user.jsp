<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<script src="https://code.jquery.com/jquery-3.6.3.js" integrity="sha256-nQLuAZGRRcILA+6dMBOvcRh5Pe310sBpanc6+QBmyVM=" crossorigin="anonymous"></script> <%-- CDN 절대링크 --%>
<script src="http://cdnjs.cloudflare.com/ajax/libs/jquery-easing/1.3/jquery.easing.min.js"></script> <%-- CDN 절대링크 --%>
<script src="<%=request.getContextPath()%>/js/cs.js"></script>
<script src="https://code.jquery.com/jquery-3.6.3.js" integrity="sha256-nQLuAZGRRcILA+6dMBOvcRh5Pe310sBpanc6+QBmyVM=" crossorigin="anonymous"></script>

<title>HealthJava 관리자 문의답글</title>

<style type="text/css">
.adminMainpage {
	width: 1400px;
	height: 250px;
	position: relative;
	left: 50%;
	transform: translateX(-50%);
}

.profile_img {
	width: 1400px;
	height: 200px;
	padding-left: 50px;
	padding-right: 100px;
	background-color: #b21949;
}


/*Admin Page 지정*/
.name {
	padding-top: 30px;
	padding-left: 10px;
	padding-right: 1000px;
	font-family: 'KIMM_Bold';
}

.myinfo {
	padding-left: 170px;
	padding-right: 100px;
	font-family: 'KIMM_Bold';
	color: white;
}

.myinfo_date {
	padding-left: 170px;
	padding-right: 100px;
	font-family: 'KIMM_Bold';
	color: white;
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


.inquire-notice-div{ 
    padding-top: 20px;
	position:relative;
	left:17%;
	ont-size: unset;
	font-family: 'KIMM_Bold';
	margin: unset;
    height: 120px;
    width: 1400px;
}
.inquire-table-div{
	width: 90%;
  	max-width: 700px;
  	padding: 40px 20px;
  	border: 2px solid #b21949;
  	border-radius: 16px;
  	margin: 20px auto;
  	font-family: 'KIMM_Bold';
}
#label_h3{
	font-size: 30px;
	background-color:white;
	position : relative;
	left:17%;
	top:25px;
	font-family: 'KIMM_Bold';
	margin: unset;
    height: 40px;
    width: 1400px;
}
#notice1{
	color:red;
	font-family: 'KIMM_Bold';
}
hr{ 
	border: 3px;
 	height: 2px; /* hr 높이 설정 */
 	background-color: #f5ad56; /* hr 색상 설정 */
 	margin: 25px 10px; /* hr 위아래 간격 설정 */
}
p{
	font-size: medium;
	background-color:white;
} 
#texts{
	width: 100%;
	max-width:600px;
	height:150px;
	resize: none;
}

#button1 {
  font-size: 0.9rem;
  letter-spacing: -.02rem;
  width: 180px;
  margin: 0 auto;
  padding: .6rem;
  border: 1px solid rgba(0, 0, 0, 0.2);
  border-radius: 4px;
  transition: 0.1s;
  cursor: pointer;
  font-family: 'KIMM_Bold';
  background: #FC5400;
  color: white;
}

#button1:hover {
  border: 1px solid rgba(0, 0, 0, 0.3);
}

.btn-default {
  background: #f6f6f6;
  color: #111;
  background: #eee;
}

.btn-default:hover {
  background: #e1e1e1;
}

.btn-rank2 {
  background: #444;
  color: #fff;
}

.btn-rank2:hover {
  background: #222;
}

.flex-box {
  width: 100%;
  display: flex;
  flex-direction: row;
  gap: 10px;
  align-items: center;
  vertical-align: middle;
}

.file-box {
  position: relative;
  display: inline-block;
}

.file-box label {
  display: inline-block;
  padding: 10px 20px;
  color: #999;
  background: #eee;
  cursor: pointer;
  border: 1px solid #ddd;
  border-radius: 4px;
  transition: all 0.2s;
}

.file-box label:hover {
  color: #999;
  background: #e4e4e4;
  border: 1px solid #d4d4d4;
}

.file-box input[type="file"] {
  position: absolute;
  width: 0;
  height: 0;
  padding: 0;
  overflow: hidden;
  border: 0;
}

.inquire-table{
	border-spacing: 10px;
	border-collapse: separate;
	align: center;
}

input[type="text"] {
  width: 100%;
  max-width: 600px;
  font-family: 'KIMM_Bold';
}

#inquire_select{
	width:100%;
	max-width:600px;
	font-family: 'KIMM_Bold';
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
#btn {
	border-color: #b21949; 
	background-color: #b21949; 
	color: #fff;
}
</style>
<header>
<%-- header include --%>
<jsp:include page="../include/header.jsp"/>
</header>
</head>
<body>
<%-- 전체 영역 --%>
	<div class="wrap">
		<%-- 헤더 영역 --%>
		
		<%-- 본문 영역(ui깨질시 본인이 ui 수정바람..) --%>
		<section>
			<div class="main">
				<div class="inquire-table-div">
				  <input type="hidden" name="client_no" value="${cvo.client_no}">
				   <table align="center" class="inquire-table"> 
				    <tr> 
				    	<th rowspan="2" align="center">문의 유형</th> 
				    	<td><input type="text" value="${cvo.client_category }" readonly ></td>
				    </tr>
				    		
				    <th></th>
				    				    		    			     
				    <tr>
					     <th align="center" >작성자</th>
					     <td><input type="text" value="${cvo.user_id }" readonly ></td>
				    </tr>
				    
				    <tr>
					    <th>제목</th>
					    <td><input type="text" value="${cvo.client_title }" class="rag-title" name="reg-title" readonly ></td>
				    </tr>
				    
				    <tr>
					    <th>문의내용</th>
					    <td><textarea cols="30" rows="3" readonly >${cvo.client_cont }</textarea></td>
				    </tr>
				    
				    <tr>
				    <th>문의 답글</th>
				    <td>
					    <c:if test="${cvo.client_cont_reply  != ' '}">
					    <textarea cols="30" rows="3" name="client_cont_reply" readonly >${cvo.client_cont_reply}</textarea>
					    </c:if>
					    
					     <c:if test="${cvo.client_cont_reply == ' ' }">
					    <textarea cols="30" rows="3" placeholder="아직 답변이 등록되지 않았습니다." name="client_cont_reply" readonly ></textarea>
					    </c:if>					    
				    </td>
				    </tr>
     				</table>
     				<input id="btn" type="button" value="목록으로" onclick="location ='contact';" >
     			</div>
				
				</div> <%-- end board --%>
				
			
			<%-- top버튼 삭제 X --%>
			<div id="topBtn">
				<span class="fonti um-arrow-circle-up um-3x icon"></span>TOP
			</div>
		</section>

	<%-- 푸터 영역 --%>
	<footer>
	<!-- footer -->
	<jsp:include page="../include/footer.jsp" />
	<!-- footer 끝 -->
	</footer>
	</div><%-- main 끝 --%>
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