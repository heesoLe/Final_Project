package shop.HealthJava.controller;

import java.util.List;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import shop.HealthJava.service.ChatService;
import shop.HealthJava.vo.ChatRoomVO;

@Controller
public class ChatController {
	
    @Autowired
    private ChatService chatService;
    
    
    @GetMapping("/chat")
    public String chatGET(HttpSession session) { // 채팅 페이지 접속
        System.out.println("@ChatController, chat GET()");
        System.out.println("채팅 페이지 접속 완료");
        
        return "chat";
    }
    
    // 채팅창 모달
    @RequestMapping("/chatmodal")
    public ModelAndView chatModal() {
        ModelAndView chatModalForm = new ModelAndView("chat/chatmodal"); // 페이지 경로
        return chatModalForm;
    }
    
    // 채팅창 팝업
    @RequestMapping("/chatting")
    public ModelAndView chatPage() {
    	ModelAndView chattingForm = new ModelAndView("chat/chatting"); // 페이지 경로
        return chattingForm;
    }
    
    // 채팅방 목록 조회
    @GetMapping(value = "/chat/rooms")
    public ModelAndView rooms(ModelAndView mv) {
        System.out.println("# 채팅방 전체 목록");
        List<ChatRoomVO> roomList = chatService.findAllRooms(); // Update the method call to getAllChatRooms()
        mv.addObject("list", roomList);
        return mv;
    }

    // 채팅방 개설
    @PostMapping(value = "/chat/room")
    public String create(@RequestParam String name, RedirectAttributes rttr) {
        ChatRoomVO room = chatService.createChatRoomVO(name);
        System.out.println("# 채팅방이 생성되었습니다, 채팅방 이름은: " + name + ", 채팅방 아이디는: " + room.getRoomId());
        rttr.addFlashAttribute("roomName", room);
        return "redirect:/chatting"; // chatting Logo 있는 부분
    }

    // 생성된 채팅방 들어가기
    @GetMapping("/chat/room")
    public void getRoom(String roomId, Model model){
        System.out.println("# 채팅방에 접속합니다, 채팅방 아이디는 : " + roomId);
        model.addAttribute("room", chatService.findRoomById(roomId));
    }
}