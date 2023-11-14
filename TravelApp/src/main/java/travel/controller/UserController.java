package travel.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import travel.model.User;
import travel.service.UserService;

@Controller
public class UserController {
	
	@Autowired
	private UserService userService;
	
	
	// sends to register page
	@GetMapping("/register")
	public String getRegisterPage(Model model) {
		model.addAttribute("registerRequest", new User());
		return "register";
	}
	
	//sends to login page
	@GetMapping("/login")
	public String getLoginPage(Model model) {
		model.addAttribute("loginRequest", new User());
		return "login";
	}
	
	// fixes index
	@GetMapping("/")
	public String getIndex() {
		return "index";
	}
	
	// other index call
	@GetMapping("/index")
	public String getIndexPage() {
		return "index";
	}
	
	// sends to error_page
	@GetMapping("/error_page")
	public String getErrorPage() {
		return "error_page";
	}
	
	// what does it do with registered users?
	@PostMapping("/register")
	public String register(@ModelAttribute User user) {
		System.out.println("Register request: " + user);
	    User registeredUser = userService.registerUser(user.getUsername(), user.getPassword());
	    System.out.println("Registered User: " + registeredUser);
	    return registeredUser == null ? "error_page" : "redirect:/index";
	}
	
	// what does it do with a logged in users?
	@PostMapping("/login")
    public String login() {
        // Get the currently authenticated user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        // Check if the user is authenticated
        if (authentication != null && authentication.isAuthenticated()) {
            // User is authenticated, redirect to index
            return "redirect:/index";
        } else {
            // Authentication failed, redirect to error_page
            return "error_page";
        }
    }



	
}