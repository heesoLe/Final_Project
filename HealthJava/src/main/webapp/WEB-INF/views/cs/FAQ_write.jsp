<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
</head>

<style>
.inquire-notice-div {
	padding-top: 20px;
	position: relative;
	left: 17%;
	ont-size: unset;
	font-family: 'KIMM_Bold';
	margin: unset;
	height: 120px;
	width: 1400px;
}

.inquire-table-div {
	width: 90%;
	max-width: 700px;
	padding: 40px 20px;
	border: 2px solid #b21949;
	border-radius: 16px;
	margin: 20px auto;
	font-family: 'KIMM_Bold';
}

#label_h3 {
	font-size: 30px;
	background-color: white;
	position: relative;
	left: 17%;
	top: 25px;
	font-family: 'KIMM_Bold';
	margin: unset;
	height: 40px;
	width: 1400px;
}

#notice1 {
	color: red;
	font-family: 'KIMM_Bold';
}

hr {
	border: 3px;
	height: 2px; /* hr 높이 설정 */
	background-color: #b21949; /* hr 색상 설정 */
	margin: 25px 10px; /* hr 위아래 간격 설정 */
}

p {
	font-size: medium;
	background-color: white;
}

#texts {
	width: 100%;
	max-width: 600px;
	height: 150px;
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
	background: #b21949;
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

.inquire-table {
	border-spacing: 10px;
	border-collapse: separate;
	align: center;
}

input[type="text"] {
	width: 100%;
	max-width: 600px;
	font-family: 'KIMM_Bold';
}

#inquire_select {
	width: 100%;
	max-width: 600px;
	font-family: 'KIMM_Bold';
}
</style>
<body>
	<!-- <div class="inquire-notice-div">
<form action="cs_addNoticeOK.shop" method = "post">
<table class="inquire-table">
	<tr>
		<th>제목</th>
		<td><input name="notice_title" id="notice_title" size="15" ></td>
	</tr>
	<tr>
		<th>내용</th>
		<td><textarea rows="4" cols="15" name="notice_cont" id="notice_cont"></textarea></td>
	</tr>
</table>



<div>
            <input type="submit" value="저장" /> 
            <input type="reset" value="취소" onclick="" /> 
            <input type="button" value="목록" onclick="location='cs_notice.shop';">
         </div>
         </form>
         </div> -->
	<section class="notice"> <!-- 문의 작성 폼 -->
	<p id="label_h3">FAQ 작성</p>
	<hr>
	<br>

	<div class="inquire-table-div">
		<form action="FAQ_write_ok" method="post" id="faq_write_form">
			<table class="inquire-table">
				<tr>
					<th>구분</th>
					<td><select name="faq_category"
						style="width: 500px; height: 30px;">
							<option value="로그인/정보">로그인/정보</option>
							<option value="상품">상품</option>
							<option value="주문/결제">주문/결제</option>
							<option value="배송문의">배송문의</option>
							<option value="교환/취소(반품)">교환/취소(반품)</option>
					</select></td>
				</tr>
				<tr>
				<tr>
					<th>제목</th>
					<td><input type="text" class="rag-title" name="faq_title"
						placeholder="제목을 입력하세요"></td>
				</tr>
				<tr>
					<th>문의내용</th>
					<td>
						<!-- <textarea placeholder="문의내용을 입력해주세요." maxlength="2000" rows="6" id="texts" spellcheck="false"></textarea> -->
						<textarea id="faq_cont" class="summernote" name="faq_cont"
							rows="10" cols="65"></textarea>
					</td>
				</tr>

				<tr>
					<th></th>
					<td>
						<div class="flex-box">
							<button id="button1" class="btn-rank2" onclick="write_check();">등록하기</button>
							<button type="reset" id="button1" class="btn-default"
								onclick="location='/FAQ';">취소</button>
						</div>
					</td>
				</tr>

			</table>

		</form>
	</div>

	</section>
	<script>
		
	<%-- 수정 버튼 클릭시 --%>
		function write_check() {
			var answer;
			var writeForm = document.getElementById('faq_write_form');
			answer = confirm("글을 등록하시겠습니까?");

			if (answer == true) {
				alert("글 등록이 완료되었습니다.");
				writeForm.submit();
				location.href = 'FAQ';
				return true;
			} else if (answer == false) {
				return false;
			}
		}
	</script>
</body>
</html>